#include <stdio.h>
#include <wchar.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#pragma pack(push, 1)
typedef struct {
    char     signature[4];
    uint16_t usa_offset;
    uint16_t usa_count;
    uint64_t lsn;
    uint16_t sequence_number;
    uint16_t hard_link_count;
    uint16_t first_attr_offset;
    uint16_t flags;
    uint32_t used_size;
    uint32_t allocated_size;
    uint64_t base_record;
    uint16_t next_attr_id;
    uint16_t align;
    uint32_t record_number;
} FILE_RECORD_HEADER;

typedef struct {
    uint32_t type;           // attribute type
    uint32_t length;         // total attribute length
    uint8_t  non_resident;   // 0 = resident, 1 = non-resident
    uint8_t  name_length;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t attr_id;
} ATTR_HEADER;

typedef struct {
    ATTR_HEADER common;
    uint32_t value_length;
    uint16_t value_offset;
    uint8_t  indexed_flag;
    uint8_t  padding;
} RESIDENT_ATTR_HEADER;

typedef struct {
    ATTR_HEADER common;
    uint64_t lowest_vcn;     // first cluster
    uint64_t highest_vcn;    // last cluster
    uint16_t run_offset;     // offset to data runs
    uint8_t compression_unit;
    uint8_t reserved[5];
    uint64_t alloc_size;     // attribute
    uint64_t real_size;      // attribute
    uint64_t initialized_size;    // stream data
    uint64_t compressed_size;
} NONRES_ATTR_HEADER;

typedef struct {
    RESIDENT_ATTR_HEADER resident;
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_modification_time;
    uint64_t access_time;
    uint32_t file_attributes;
    uint32_t max_versions;
    uint32_t version_number;
    uint32_t class_id;
    uint32_t owner_id;
    uint32_t security_id;
    uint64_t quota_charged;
    uint64_t usn;
} STANDARD_INFORMATION_ATTR;

typedef struct {
    RESIDENT_ATTR_HEADER resident;
    uint64_t parent_ref;
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_modification_time;
    uint64_t access_time;
    uint64_t allocated_size;
    uint64_t real_size;
    uint32_t flags;
    uint32_t reparse;
    uint8_t  name_length;
    uint8_t  name_type;
    wchar_t  name[1];
} FILE_NAME_ATTR;

typedef struct {
    uint8_t     jump[3]; 
    char        name[8];
    uint16_t    bytesPerSector;
    uint8_t     sectorsPerCluster;
    uint16_t    reservedSectors;
    uint8_t     unused0[3];
    uint16_t    unused1;
    uint8_t     media;
    uint16_t    unused2;
    uint16_t    sectorsPerTrack;
    uint16_t    headsPerCylinder;
    uint32_t    hiddenSectors;
    uint32_t    unused3;
    uint32_t    unused4;
    uint64_t    totalSectors;
    uint64_t    mftStart;
    uint64_t    mftMirrorStart;
    int8_t      clustersPerFileRecord;
    uint8_t     cfr_padding[3];
    int8_t      clustersPerIndexBlock;
    uint8_t     cib_padding[3];
    uint64_t    serialNumber;
    uint32_t    checksum;
    uint8_t     bootloader[426];
    uint16_t    bootSignature;
} BootSector;
#pragma pack(pop)

typedef struct {
    uint32_t recno;
    uint64_t frn;
    uint64_t parent_frn;
    char *name;
    uint16_t name_len;
} LinkEntry;

typedef struct {
    uint64_t frn;
    uint64_t parent_frn;
    uint32_t record_number;
    uint16_t sequence_number;
    uint64_t record_offset;
    char *name;
    uint16_t name_len;
    uint64_t size;
    char *dir_path_cache;
    uint8_t dir_path_ready;
    uint8_t in_use;
    uint8_t is_dir;
    uint8_t is_ads;
    uint16_t hard_link_count;
    uint32_t file_attribs;
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_modification_time;
    uint64_t access_time;
} FileEntry;

LinkEntry *links = NULL;
uint32_t link_count = 0;
uint32_t link_capacity = 0;
FileEntry *entries = NULL;
uint32_t entry_capacity = 0;
#define CHUNK_SIZE (64ULL * 1024ULL * 1024ULL)  //  read mft in 64MB chunks
#define TICKS_PER_SECOND 10000000ULL  // 100ns tick
#define TICKS_BTWN_1601_1970 116444736000000000ULL
// #define OUTBUF_SIZE (1024 * 1024) // 1MB
#define OUTBUF_SIZE (4 << 20)

// prototypes
uint64_t EpochToNtfs(time_t epoch);
uint64_t ParseDatetimeToNtfs(const char *input);
time_t NtfsToEpoch(uint64_t ntfs);
void FormatFileTime(uint64_t ft, char *out, size_t outSize);

uint32_t GetFileRecordSize(const BootSector *bs) {
    int8_t c = bs->clustersPerFileRecord;

    if (c > 0) {
        return (uint32_t)c * (uint32_t)bs->bytesPerSector * (uint32_t)bs->sectorsPerCluster;
    } else {
        return 1U << (-c);
    }
}

int apply_usa(unsigned char *buf, uint16_t bytesPerSector) {
    FILE_RECORD_HEADER *hrec = (FILE_RECORD_HEADER *)buf;

    uint16_t *usa = (uint16_t *)(buf + hrec->usa_offset);
    uint16_t usn = usa[0];

    uint16_t count = hrec->usa_count; // total entries (USN + fixups)

    for (uint16_t i = 0; i < count - 1; i++) {
        uint16_t *sectorEnd = (uint16_t *)(buf + ((i + 1) * bytesPerSector) - 2);

        // check
        if (*sectorEnd != usn) {
            return 0; // corrupted
        }

        // restore
        *sectorEnd = usa[i + 1];
    }

    return 1;
}

void Read(HANDLE drive, void *buffer, uint64_t from, DWORD count) {
    LARGE_INTEGER pos;
    DWORD bytesRead = 0;

    pos.QuadPart = (LONGLONG)from;

    if (!SetFilePointerEx(drive, pos, NULL, FILE_BEGIN)) {
        fprintf(stderr, "SetFilePointerEx failed: %lu\n", GetLastError());
        exit(1);
    }

    if (!ReadFile(drive, buffer, count, &bytesRead, NULL)) {
        fprintf(stderr, "ReadFile failed: %lu\n", GetLastError());
        exit(1);
    }

    if (bytesRead != count) {
        fprintf(stderr, "Short read: got %lu bytes, expected %lu\n",
                bytesRead, count);
        exit(1);
    }
}

void EnsureLinkCapacity(void) {
    if (link_count < link_capacity)
        return;

    uint32_t new_capacity = link_capacity ? link_capacity * 2 : 1024;

    LinkEntry *new_links = realloc(links, new_capacity * sizeof(LinkEntry));
    if (!new_links) {
        printf("link capacity realloc failed\n");
        exit(1);
    }

    links = new_links;
    link_capacity = new_capacity;
}

void EnsureEntryCapacity(uint32_t recno) {
    if (recno < entry_capacity)
        return;
    // printf("EnsureEntryCapacity recno=%lu\n", (unsigned long)recno);  // debug disabled for performance
    uint32_t new_capacity = entry_capacity ? entry_capacity : 1024;

    while (new_capacity <= recno) {
        if (new_capacity > UINT32_MAX / 2) {
            printf("ensure capacity overflow\n");
            exit(1);
        }
        new_capacity *= 2;
    }

    FileEntry *new_entries = (FileEntry *)realloc(entries, new_capacity * sizeof(FileEntry));
    if (!new_entries) {
        printf("ensure capacity realloc failed\n");
        exit(1);
    }

    memset(new_entries + entry_capacity, 0,
           (new_capacity - entry_capacity) * sizeof(FileEntry));

    entries = new_entries;
    entry_capacity = new_capacity;
}

void AppendLink(uint32_t recno, uint64_t frn, uint64_t parent_frn, const char *name) {
    EnsureLinkCapacity();
    links[link_count].recno = recno;
    links[link_count].frn = frn;
    links[link_count].parent_frn = parent_frn;
    links[link_count].name = _strdup(name);
    links[link_count].name_len = strlen(name);
    if (!links[link_count].name) {
        printf("strdup failed\n");
        exit(1);
    }
    link_count++;
}

void ProcessRecord(unsigned char *buf, uint16_t bytesPerSector, uint32_t recno, uint32_t record_size) {
    FILE_RECORD_HEADER *hrec;
    ATTR_HEADER *attr;

    uint64_t frn = 0;    
    uint32_t file_attribs = 0;
    uint64_t creation_time = 0;
    uint64_t modification_time = 0;
    uint64_t mft_modification_time = 0;
    uint64_t access_time = 0;
    
    uint8_t got_name = 0;
    uint8_t got_best_name = 0;
    // int p = 0;  // links appended

    char best_name[1024] = {0};
    uint16_t best_name_len = 0;
    uint64_t best_parent_frn = 0;

    char name[1024] = {0};
    uint64_t size = 0;

    uint8_t is_dir = 0;
    uint8_t is_ads = 0;


    hrec = (FILE_RECORD_HEADER *)buf;
    if (hrec->first_attr_offset >= record_size)
        return;

    if (!apply_usa(buf, bytesPerSector)) // apply fixups
        return;
    if (memcmp(hrec->signature, "FILE", 4) != 0)  // sanity check is there a header
        return;
    // not in use
    if (!(hrec->flags & 0x0001))
        return;
    is_dir = (hrec->flags & 0x0002) ? 1 : 0;

    if (hrec->base_record != 0) {
        return;
        // frn = hrec->base_record;  // not processing all hardlinks
    } else {
        frn = ((uint64_t)hrec->sequence_number << 48) | hrec->record_number;  // frn = ((uint64_t)hrec->sequence_number << 48) | recno;  // original. inferred
    }
    attr = (ATTR_HEADER *)(buf + hrec->first_attr_offset);

    while (1) {
        if ((unsigned char *)attr + sizeof(ATTR_HEADER) > buf + record_size)
            break;
        if (attr->type == 0xFFFFFFFF || attr->length == 0)
            break;
        if (attr->length < sizeof(ATTR_HEADER))
            break;
        if ((unsigned char *)attr + attr->length > buf + record_size)
            break;
        if (attr->type == 0x10 && attr->non_resident == 0) {
            STANDARD_INFORMATION_ATTR *si = (STANDARD_INFORMATION_ATTR *)attr;
            file_attribs = si->file_attributes;
            creation_time = si->creation_time;
            modification_time = si->modification_time;
            mft_modification_time = si->mft_modification_time;
            access_time = si->access_time;

        }
        // if (attr->type == 0x20) {
            // are other $FILE_NAME attributes in extension records?
        // }
        if (attr->type == 0x30 && attr->non_resident == 0) {
            FILE_NAME_ATTR *fn = (FILE_NAME_ATTR *)attr;

            if (fn->name_length < 512) {
                wchar_t wname[512];

                wmemcpy(wname, fn->name, fn->name_length);
                wname[fn->name_length] = L'\0';

                int len = WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    wname,
                    -1,
                    name,
                    sizeof(name),
                    NULL,
                    NULL
                );
                if (len == 0) {
                    attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
                    continue;
                }
                // if (len == sizeof(name)) {
                    //// detect truncation
                    // continue;
                // }

                size_t name_len = (size_t)(len - 1);
                if (name_len >= sizeof(best_name)) {
                    attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
                    continue;
                }
                bool found = false; // marker so itself isnt appended to links
                // get the first name prefer Windows or Windows&Dos
                if (!got_best_name) {
                    got_name = 1;

                    // strcpy(best_name, name);  // 04/09/2026 commented out
                    memcpy(best_name, name, name_len + 1);
                    best_name_len = (uint16_t)name_len;

                    best_parent_frn = fn->parent_ref;
                    // size = fn->real_size;

                    if (fn->name_type == 1 || fn->name_type == 3) {
                        got_best_name = 1;
                        found = true;
                    }
                }


                if ((!found && !is_dir) && (fn->name_type != 2) &&
                    hrec->base_record == 0 &&
                    hrec->hard_link_count > 1) {
                    AppendLink((uint32_t)(frn & 0x0000FFFFFFFFFFFFULL), frn, fn->parent_ref, name);  // use reference no as first arg
                }
            }
        }
        // done parsing $FILE_NAME
        // if (attr->type == 0x40) {
            // break;
        // }
        if (attr->type == 0x80) {
            if (attr->name_length != 0) {
                // skip ADS
                // attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
                // continue;
                is_ads = 1;
                break;
            }
            if (attr->non_resident == 0) {
                RESIDENT_ATTR_HEADER *ndata = (RESIDENT_ATTR_HEADER *)attr;
                size = ndata->value_length;

            } else {
                NONRES_ATTR_HEADER *ndata = (NONRES_ATTR_HEADER *)attr;
                size = ndata->real_size;
            }


        }
        attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
    }

    if (hrec->base_record == 0 && got_name) {

        EnsureEntryCapacity(recno);
        entries[recno].frn = frn;
        entries[recno].parent_frn = best_parent_frn;
        entries[recno].record_number = hrec->record_number;
        entries[recno].sequence_number = hrec->sequence_number;
        entries[recno].record_offset = hrec->record_number * record_size;
        // free(entries[recno].name);  // if already assign
        entries[recno].name = _strdup(best_name);
        if (!entries[recno].name) {
            entries[recno].in_use = 0;
            return;
        }
        entries[recno].name_len = best_name_len;
        // entries[recno].name_len = strlen(best_name);  // 04/09/2026 commented out
        entries[recno].size = size;
        entries[recno].in_use = 1;
        entries[recno].is_dir = is_dir;
        entries[recno].is_ads = is_ads;
        entries[recno].hard_link_count = hrec->hard_link_count;
        // entries[recno].links_appended = p;
        entries[recno].file_attribs = file_attribs;

        // uint8_t is_reparse = 0;
        // is_reparse = (si->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;
        // entries[recno].is_reparse = is_reparse;
        
        entries[recno].creation_time = creation_time;
        entries[recno].modification_time = modification_time;
        entries[recno].mft_modification_time = mft_modification_time;
        entries[recno].access_time = access_time;
    }
}

uint32_t ProcessRun(HANDLE h, uint64_t lcn, uint64_t clusters, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t startRecno, uint32_t record_size) {
    uint64_t runBytes = clusters * bytesPerCluster;
    uint64_t offset = lcn * bytesPerCluster;
    unsigned char *buffer = malloc((size_t)CHUNK_SIZE);
    uint32_t processed = 0;
    if (!buffer) {
        printf("malloc failed\n");
        exit(1);
    }
    
    while (runBytes > 0) {
        uint64_t chunk = runBytes > CHUNK_SIZE ? CHUNK_SIZE : runBytes;
        uint64_t records = chunk / record_size;

        Read(h, buffer, offset, (DWORD)chunk);

        for (uint64_t i = 0; i < records; i++) {
            ProcessRecord(buffer + (i * record_size), bytesPerSector, startRecno + (uint32_t)i, record_size);
            processed++;
        }

        startRecno += (uint32_t)records;
        offset += chunk;
        runBytes -= chunk;
    }

    free(buffer);
    return processed;
}

void ParseRuns(HANDLE h, unsigned char *run, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t record_size, bool has_target) {

    int64_t currentLCN = 0;
    uint32_t currentRecno = 0;
    int run_number = 0;

    while (*run != 0) {
        uint8_t header = *run++;
        uint8_t lengthSize = header & 0x0F;
        uint8_t offsetSize = (header >> 4) & 0x0F;
        uint64_t runLength = 0;
        int64_t runOffset = 0;
        uint8_t i = 0;
        if (lengthSize == 0)
            break;

        for (i = 0; i < lengthSize; i++) {
            runLength |= ((uint64_t)run[i]) << (i * 8);
        }
        run += lengthSize;

        if (offsetSize == 0) {
            run_number++;
            if (has_target) {
                printf("=== SPARSE RUN ===\n");
                printf("Run %d: LCN=%lld clusters=%llu byte_offset=%llu bytes=%llu\n", run_number, (long long)currentLCN,
                    (unsigned long long)runLength, (unsigned long long)(currentLCN * bytesPerCluster),
                    (unsigned long long)(runLength * bytesPerCluster));
            }
            currentRecno += (uint32_t)((runLength * bytesPerCluster) / record_size);
            continue;
        }

        for (i = 0; i < offsetSize; i++) {
            runOffset |= ((int64_t)run[i]) << (i * 8);
        }

        if (offsetSize > 0 && (run[offsetSize - 1] & 0x80)) {
            runOffset |= -((int64_t)1 << (offsetSize * 8));
        }

        run += offsetSize;

        currentLCN += runOffset;

        uint32_t processed = ProcessRun(h, currentLCN, runLength, bytesPerCluster, bytesPerSector, currentRecno, record_size);
        currentRecno += processed;
        run_number++;
        // currentRecno += (uint32_t)((runLength * bytesPerCluster) / record_size);  // original

        // mft run data for run_number
        // printf("Run %d: LCN=%lld clusters=%llu byte_offset=%llu bytes=%llu\n", x, (long long)currentLCN,
            // (unsigned long long)runLength, (unsigned long long)(currentLCN * bytesPerCluster),
            // (unsigned long long)(runLength * bytesPerCluster));

        // debug
        // uint64_t runBytes = runLength * bytesPerCluster;
        // if (runBytes % record_size != 0)
            // printf("warning: run not aligned to record size\n");
    }
}

int BuildLinkPath(uint32_t link_index, char *out, size_t outSize) {
    uint32_t chain[1024];
    size_t depth = 0;
    size_t pos = 0;
    uint64_t parent_frn;
    uint32_t recno;

    if (!out || outSize == 0)
        return 0;

    if (link_index >= link_count)
        return 0;


    out[0] = '\0';

    if (!links[link_index].name)
        return 0;

    parent_frn = links[link_index].parent_frn;

    while (1) {
        recno = (uint32_t)(parent_frn & 0x0000FFFFFFFFFFFFULL);

        if (recno >= entry_capacity)
            return 0;

        if (!entries[recno].in_use)
            return 0;

        if (depth >= 1024)
            return 0;

        for (size_t j = 0; j < depth; j++) {
            if (chain[j] == recno) {
                return 0;
            }
        }

        chain[depth++] = recno;

        if (recno == 5)
            break;

        uint64_t next_parent = entries[recno].parent_frn;
        uint32_t parent_recno = (uint32_t)(next_parent & 0x0000FFFFFFFFFFFFULL);
        uint16_t parent_seq = (uint16_t)(next_parent >> 48);

        if (parent_recno == recno)
            return 0;

        if (parent_recno >= entry_capacity)
            return 0;

        if (!entries[parent_recno].in_use)
            return 0;

        uint16_t actual_seq = (uint16_t)(entries[parent_recno].frn >> 48);
        if (actual_seq != parent_seq)
            return 0;

        parent_frn = next_parent;
    }

    for (size_t i = depth; i > 0; i--) {
        uint32_t idx = chain[i - 1];
        const char *name = entries[idx].name;
        size_t len;

        if (!name || name[0] == '\0')
            continue;

        if (strcmp(name, ".") == 0)
            continue;

        if (pos + 1 >= outSize)
            return 0;

        out[pos++] = '\\';
        out[pos] = '\0';

        len = entries[idx].name_len;
        // len = strlen(name);
        if (len > 255)
            return 0;

        if (pos + len >= outSize)
            return 0;

        memcpy(out + pos, name, len);
        pos += len;
        out[pos] = '\0';
    }

    if (pos + 1 >= outSize)
        return 0;

    out[pos++] = '\\';
    out[pos] = '\0';

    const char *leaf = links[link_index].name;
    size_t len = links[link_index].name_len;
    // size_t len = strlen(leaf);

    if (len > 255)
        return 0;

    if (pos + len >= outSize)
        return 0;

    memcpy(out + pos, leaf, len);
    pos += len;
    out[pos] = '\0';

    return 1;
}

int BuildDirPath(uint32_t recno, char *out, size_t outSize) {
    uint32_t orig_recno = recno;
    uint32_t chain[1024];
    size_t depth = 0;
    size_t pos = 0;

    if (!out || outSize == 0)
        return 0;

    out[0] = '\0';

    if (orig_recno >= entry_capacity)
        return 0;

    if (!entries[orig_recno].in_use)
        return 0;

    if (entries[orig_recno].dir_path_ready && entries[orig_recno].dir_path_cache) {
        strncpy(out, entries[orig_recno].dir_path_cache, outSize - 1);
        out[outSize - 1] = '\0';
        return 1;
    }

    // files use parent directory, dirs use themselves
    if (!entries[orig_recno].is_dir) {
        uint64_t parent_frn = entries[orig_recno].parent_frn;
        uint32_t parent_recno = (uint32_t)(parent_frn & 0x0000FFFFFFFFFFFFULL);
        uint16_t parent_seq = (uint16_t)(parent_frn >> 48);

        if (parent_recno >= entry_capacity)
            return 0;
        if (!entries[parent_recno].in_use)
            return 0;
        if ((uint16_t)(entries[parent_recno].frn >> 48) != parent_seq)
            return 0;

        recno = parent_recno;
    }

    while (1) {
        if (recno >= entry_capacity)
            return 0;

        if (!entries[recno].in_use)
            return 0;

        if (depth >= 1024)
            return 0;

        for (size_t j = 0; j < depth; j++) {
            if (chain[j] == recno)
                return 0;
        }

        chain[depth++] = recno;

        if (recno == 5)
            break;

        uint64_t parent_frn = entries[recno].parent_frn;
        uint32_t parent_recno = (uint32_t)(parent_frn & 0x0000FFFFFFFFFFFFULL);
        uint16_t parent_seq = (uint16_t)(parent_frn >> 48);

        if (parent_recno == recno)
            return 0;
        if (parent_recno >= entry_capacity)
            return 0;
        if (!entries[parent_recno].in_use)
            return 0;
        if ((uint16_t)(entries[parent_recno].frn >> 48) != parent_seq)
            return 0;

        recno = parent_recno;
    }

    for (size_t i = depth; i > 0; i--) {
        const char *name = entries[chain[i - 1]].name;
        size_t len;

        if (!name || name[0] == '\0')
            continue;
        if (strcmp(name, ".") == 0)
            continue;

        if (pos + 1 >= outSize)
            return 0;

        out[pos++] = '\\';
        out[pos] = '\0';

        len = entries[chain[i - 1]].name_len;
        // len = strlen(name);
        if (pos + len >= outSize)
            return 0;

        memcpy(out + pos, name, len);
        pos += len;
        out[pos] = '\0';
    }

    if (pos == 0) {
        if (outSize < 2)
            return 0;
        strcpy(out, "\\");
    }

    char *tmp = _strdup(out);
    if (!tmp) return 0;

    free(entries[orig_recno].dir_path_cache);
    entries[orig_recno].dir_path_cache = tmp;
    entries[orig_recno].dir_path_ready = 1;
    
    return 1;
}

int BuildPath(uint32_t recno, char *out, size_t outSize) {
    char dir[8192];
    const char *name;
    size_t pos, len;

    if (!out || outSize == 0)
        return 0;

    out[0] = '\0';

    if (recno >= entry_capacity)
        return 0;
    if (!entries[recno].in_use)
        return 0;

    // initially build the dir path
    if (!BuildDirPath(recno, dir, sizeof(dir)))
        return 0;
    
    // direcory just uses parent path
    // files uses full path. if failure as in no name or otherwise return path so can be debugged
    name = entries[recno].name;
    if (entries[recno].is_dir || !name || name[0] == '\0') {
        strncpy(out, dir, outSize - 1);
        out[outSize - 1] = '\0';
        return 1;
    }
    // now build the file path
    strncpy(out, dir, outSize - 1);
    out[outSize - 1] = '\0';
    pos = strlen(out);

    // empty path use one \\.
    if (pos == 0) {
        if (outSize < 2)
            return 0;
        strcpy(out, "\\");
        pos = 1;
    }

    if (strcmp(name, ".") == 0)
        return 1;

    // add the \\ before filename
    if (pos > 1) {
        if (pos + 1 >= outSize)
            return 0;
        out[pos++] = '\\';
        out[pos] = '\0';
    }

    len = entries[recno].name_len;
    // len = strlen(name);
    if (pos + len >= outSize)
        return 0;

    memcpy(out + pos, name, len);
    pos += len;
    out[pos] = '\0';

    return 1;
}

/**
with no argument output all valid file entries from the MFT


or can take 1 argument

search for files by cutoff
--cutoff "2026-03-19 10:13:18" or 2026-03-19T10:13:18

diagnostics\list mft record
--target <record number>

output for Qt gui which is same as no argument different format 
--parse
*/
int main(int argc, char *argv[]) {

    int ret = 1;  // assume error
    setvbuf(stdout, NULL, _IOFBF, 4 << 20);  // enable buffering
    int arg_index = 1;

    char *drive = "C:";  // default

    char drive_buf[3];

    if (argc >= 2 && strlen(argv[1]) >= 2 && argv[1][1] == ':') {
        drive_buf[0] = argv[1][0];
        drive_buf[1] = ':';
        drive_buf[2] = '\0';

        drive = drive_buf;
        arg_index = 2;  // shift
    }

    char volume[16];  // set target drive ie C: S: E:

    snprintf(volume, sizeof(volume), "\\\\.\\%s", drive);
    // const char *volume = "\\\\.\\C:";  // original moved to drive arg
    
    
    uint64_t cutoff_time = 0;

    uint32_t target_recno = 0;
    bool has_target = false;

    bool qt_output = false;

    // read any drive and or one optional argument

    if (argc > arg_index) {

        char arg_buf[64];
        char *t;

        if (strcmp(argv[arg_index], "--cutoff") == 0) {
            if (argc <= arg_index + 1) {
                printf("--cutoff requires a datetime\n");
                return 1;
            }

            // parse out any 'T' for format "2026-03-19T10:13:18" ISO 8601
            strncpy(arg_buf, argv[arg_index + 1], sizeof(arg_buf) - 1);
            arg_buf[sizeof(arg_buf) - 1] = '\0';
            t = strchr(arg_buf, 'T');
            if (t) {
                *t = ' ';
            }            

            cutoff_time = ParseDatetimeToNtfs(arg_buf);  // const char *input = argv[1]; original prototype for sscanf using ParseDatetimeToNtfs
            if (cutoff_time == 0) {
                printf("Invalid datetime format 2026-03-19T10:13:18 or \"2026-03-19 10:13:18\" \n");
                return 1;            
            }

        } else if (strcmp(argv[arg_index], "--target") == 0) {
            if (argc <= arg_index + 1) {
                printf("--target requires a record number\n");
                return 1;
            }

            unsigned long val = strtoul(argv[arg_index + 1], &t, 10);
            if (*t != '\0') {
                printf("Invalid target %s\n", argv[arg_index + 1]);
                return 1;
            }

            target_recno = (uint32_t)val;
            has_target = true;

        } else if (strcmp(argv[arg_index], "--parse") == 0) {
            qt_output = true;

        } else {
            printf("Unknown option %s\n", argv[arg_index]);
            return 1;
        }
    }

    // original prototype
    // const uint64_t mft_offset = 0xC0000000ULL; // used fsutil fsinfo ntfsinfo C: for starting cluster.
    // const DWORD record_size = 1024;  // assumed same as 512 for sector

    HANDLE h;
    LARGE_INTEGER pos;
    // unsigned char buf[1024];
    unsigned char *buf = NULL;
    // unsigned char *buf = malloc(record_size);
    // if (!buf) {
        // printf("malloc failed\n");
        // goto cleanup;
    // }
    DWORD bytes_read = 0;

    FILE_RECORD_HEADER *hrec;

    h = CreateFileA(
        volume,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();

        if (err == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "Access denied. Run as administrator.\n");
        } else if (err == ERROR_NOT_READY) {
            fprintf(stderr, "Drive not ready.\n");
        } else if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            fprintf(stderr, "Invalid drive %s\n", volume); 
        } else {
            fprintf(stderr, "Failed to open %s (error %lu)\n", volume, err);
        }

        goto cleanup;
    }

    BootSector bootsector;
    Read(h, &bootsector, 0, sizeof(bootsector));
   
    /* verify drive */
    if (bootsector.bootSignature != 0xAA55) {
        printf("Invalid boot sector signature\n");
        goto cleanup;
    }
    if (memcmp(bootsector.name, "NTFS    ", 8) != 0) {
        printf("Not an NTFS volume\n");
        goto cleanup;
    }

    uint32_t record_size = GetFileRecordSize(&bootsector);
    
    uint64_t bytesPerCluster = (uint64_t)bootsector.bytesPerSector * bootsector.sectorsPerCluster;

    uint64_t mftOffset = bootsector.mftStart * bytesPerCluster;
    
    // these are listed below in has_target debug mode

    buf = malloc(record_size);
    if (!buf) {
        printf("malloc failed\n");
        goto cleanup;
    }

    // record record 0
    Read(h, buf, mftOffset, record_size);  

    hrec = (FILE_RECORD_HEADER *)buf;

    // print if diagnostic mode
    if (has_target) {
        printf("Record size:           %u\n", record_size);
        printf("Bytes per cluster:     %llu\n", (unsigned long long)bytesPerCluster);
        printf("Mft offset:            %llu\n", (unsigned long long)mftOffset);
        printf("\n");
        printf("Signature           : %.4s\n", hrec->signature);
        printf("USA offset          : %u\n", hrec->usa_offset);
        printf("USA count           : %u\n", hrec->usa_count);
        printf("Sequence number     : %u\n", hrec->sequence_number);
        printf("Hard link count     : %u\n", hrec->hard_link_count);
        printf("First attr offset   : %u\n", hrec->first_attr_offset);
        printf("Flags               : 0x%04x\n", hrec->flags);
        printf("Used size           : %u\n", hrec->used_size);
        printf("Allocated size      : %u\n", hrec->allocated_size);
        printf("Base record         : %llu\n", (unsigned long long)hrec->base_record);
        printf("Next attr id        : %u\n", hrec->next_attr_id);
        printf("Record number       : %u\n", hrec->record_number);
    }

    if (!apply_usa(buf, bootsector.bytesPerSector)) {
        printf("USA fixup failed\n");
        goto cleanup;
    }

    if (memcmp(hrec->signature, "FILE", 4) != 0) {
        printf("Invalid MFT record signature (expected FILE)\n");
        goto cleanup;
    } // } else {
        // printf("Looks like a FILE record\n");  // success
    // }
        
    // read mft header
    ATTR_HEADER *attr = (ATTR_HEADER *)(buf + hrec->first_attr_offset);

    while ((unsigned char *)attr < buf + record_size) {
        if (attr->type == 0xFFFFFFFF) {
            break;
        }

        if (attr->length == 0) {
            break;
        }

        // if (has_target) {
            // printf("Attr type: 0x%08x len=%u nonresident=%u\n",
                // attr->type, attr->length, attr->non_resident);
        // }

        if (attr->type == 0x80) {
            if (!attr->non_resident) {
                printf("$DATA is resident\n");
                goto cleanup;
            } else {

                NONRES_ATTR_HEADER *ndata = (NONRES_ATTR_HEADER *)attr;

                uint64_t mft_size = ndata->real_size;
                uint64_t record_count = mft_size / record_size;
                printf("[RECORD]  : %llu\n", (unsigned long long)record_count);

                if (has_target) {
                    printf("$DATA is non-resident\n");
                    printf("run offset   : %u\n", ndata->run_offset);
                    printf("alloc size   : %llu\n", (unsigned long long)ndata->alloc_size);
                    printf("real size    : %llu\n", (unsigned long long)mft_size);
                    printf("init size    : %llu\n", (unsigned long long)ndata->initialized_size);
                }

                unsigned char *run = (unsigned char *)attr + ndata->run_offset;

                ParseRuns(h, run, bytesPerCluster, bootsector.bytesPerSector, record_size, has_target);

                // output area
                
                char path[8192];

                // Notes:
                // FileEntry struct available variables to print
                // uint64_t frn;
                // uint64_t parent_frn;
                // uint32_t record_number;
                // uint16_t sequence_number;
                // uint64_t record_offset;
                // char *name;
                // uint16_t name_len;
                // uint64_t size;
                // char *dir_path_cache; 
                // uint8_t dir_path_ready;
                // uint8_t in_use;
                // uint8_t is_dir;
                // uint16_t hard_link_count;
                // uint32_t file_attribs;
                // uint64_t creation_time;
                // uint64_t modification_time;
                // uint64_t mft_modification_time;
                // uint64_t access_time;
                // int links_appended;

                // python fsearchmft format search by mft Qt gui
                // mtime = line[0]
                // mtime_us = line[1]
                // c_time = line[2]
                // atime = line[3]
                // size = line[4]
                // last_modified = line[5]
                // mode_attribs = line[6]
                // hardlink = line[7]
                // inode = line[8]
                // cam = line[9]
                // file_path = line[10]

                // print mft entries for run

                // recordnumber frn parent_frn mtime ctime fileattrib isdir|name|path 
                if (cutoff_time == 0 && !has_target) {

                    for (uint32_t recno = 0; recno < entry_capacity; recno++) {
                        if (!entries[recno].in_use)
                            continue;
                        if (!entries[recno].name)
                            continue;
                        if (entries[recno].is_ads)
                            continue;

                        if (BuildPath(recno, path, sizeof(path))) {
                            
                            printf("%lu %llu %llu %llu %llu %lu %s|%s|%s\n",
                                (unsigned long)recno,
                                (unsigned long long)entries[recno].frn,
                                (unsigned long long)entries[recno].parent_frn,
                                (unsigned long long)entries[recno].modification_time,
                                (unsigned long long)entries[recno].creation_time,
                                entries[recno].file_attribs,
                                entries[recno].is_dir ? "[DIR]" : "[FILE]",
                                entries[recno].name,
                                path);
                        }
                    }

                    // print all hardlinks
                    // recordnumber frn parent_frn ishlink|name|path 
                    // for (uint32_t i = 0; i < link_count; i++) {
                        // if (BuildLinkPath(i, path, sizeof(path))) {
                            // printf("%lu %llu %llu %s|%s|%s\n",
                                // (unsigned long long)links[i].recno,
                                // (unsigned long long)links[i].frn,
                                // (unsigned long long)links[i].parent_frn,
                                // "[HLINK]"
                                // links[i].name ? links[i].name : "null",
                                // path);
                        // }
                    // }
                    
                    // check for duplicates in hard_links
                    // bool dup_found = false;
                    // for (uint32_t i = 0; i < link_count; i++) {
                        // for (uint32_t j = i + 1; j < link_count; j++) {
                            // if (links[i].parent_frn == links[j].parent_frn &&
                                // strcmp(links[i].name, links[j].name) == 0)
                            // {
                                // dup_found = true;
                                // break;
                            // }
                        // }
                        // if (dup_found) break;
                    // }
                    // printf("dup_found = %d\n", dup_found);
                    
                // search by time
                } else if (cutoff_time > 0) {

                    for (uint32_t i = 0; i < entry_capacity; i++) {
                        if (!entries[i].in_use)
                            continue;
                        if (!entries[i].name)
                            continue;
                        if (entries[i].is_ads)
                            continue;
                        if (entries[i].is_dir)
                            continue;

                        uint64_t mod_time = entries[i].modification_time;
                        uint64_t creation_time = entries[i].creation_time;
                        // verify cutoff_time matches 
                        // printf("cutoff=%llu mod_time=%llu creation_time=%llu\n",
                            // (unsigned long long)cutoff_time,
                            // (unsigned long long)mod_time,
                            // (unsigned long long)creation_time);
                        if (!(mod_time >= cutoff_time || creation_time >= cutoff_time))
                            continue;
                        if (!(BuildPath(i, path, sizeof(path)))) {
                            continue;
                        }
                        
                        printf("C:%s\n", path);

                        //
                        // printf("rec=%lu frn=%llu parent=%llu name=%s path=%s%s\n",
                            // (unsigned long)i,
                            // (unsigned long long)entries[i].frn,
                            // (unsigned long long)entries[i].parent_frn,
                            // entries[i].name,
                            // path,
                            // entries[i].is_dir ? " [DIR]" : "");

                    }
                    
                // retrieve single record
                } else if (has_target) {

                    for (uint32_t i = 0; i < entry_capacity; i++) {
                        if (!entries[i].in_use)
                            continue;
                        if (!entries[i].name)
                            continue;

                        if (i == target_recno) {
                            uint32_t attrs = entries[i].file_attribs;
                            const char *ro   = (attrs & FILE_ATTRIBUTE_READONLY) ? " [READONLY]" : "";
                            const char *hid  = (attrs & FILE_ATTRIBUTE_HIDDEN) ? " [HIDDEN]" : "";
                            const char *sys  = (attrs & FILE_ATTRIBUTE_SYSTEM) ? " [SYSTEM]" : "";
                            const char *dir  = (attrs & FILE_ATTRIBUTE_DIRECTORY) ? " [DIR]" : "";
                            const char *arc  = (attrs & FILE_ATTRIBUTE_ARCHIVE) ? " [ARCHIVE]" : "";
                            const char *rep  = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ? " [REPARSE]" : "";
                            
                            printf("=== DEBUG RECORD %u ===\n", i);
                            printf("flags=0x%08X%s%s%s%s%s%s\n",
                                attrs, ro, hid, sys, dir, arc, rep);
                            // printf("file_attributes=0x%08X\n", entries[i].file_attribs);

                            printf("frn=%llu\n", (unsigned long long)entries[i].frn);
                            printf("parent_frn=%llu\n", (unsigned long long)entries[i].parent_frn);
                            
                            printf("rec=%u\n", entries[i].record_number);
                            printf("seq=%u\n", entries[i].sequence_number);
                            printf("offset=%llu hex=0x%llx\n", 
                                (unsigned long long)entries[i].record_offset,
                                (unsigned long long)entries[i].record_offset);
                            
                            printf("name=%s\n", entries[i].name ? entries[i].name : "(null)");
                            printf("size=%llu\n", entries[i].size);
                            printf("in_use=%u\n", entries[i].in_use);
                            printf("is_dir=%u\n", entries[i].is_dir);

                            printf("hard_links=%u\n", entries[i].hard_link_count);

                            // original
                            // printf("creation=%llu\n", (unsigned long long)entries[i].creation_time);
                            // printf("modification=%llu\n", (unsigned long long)entries[i].modification_time);
                            // printf("mft_modification=%llu\n", (unsigned long long)entries[i].mft_modification_time);
                            // printf("access=%llu\n", (unsigned long long)entries[i].access_time);

                            char out[64];

                            uint64_t times[4] = {
                                entries[i].creation_time,
                                entries[i].modification_time,
                                entries[i].mft_modification_time,
                                entries[i].access_time
                            };

                            const char *labels[4] = {
                                "ctime",
                                "mtime",
                                "mft",
                                "atime"
                            };

                            for (int t = 0; t < 4; t++) {
                                FormatFileTime(times[t], out, sizeof(out));
                                printf("%s=%s\n", labels[t], out);
                            }
                            if (BuildPath(i, path, sizeof(path))) {
                                printf("path=%s\n", path);
                            } else {
                                printf("path=(failed)\n");
                            }

                            printf("========================\n");
                        }
                    }
                } else if (qt_output) {

                    for (uint32_t recno = 0; recno < entry_capacity; recno++) {
                        if (!entries[recno].in_use)
                            continue;
                        if (!entries[recno].name)
                            continue;
                        if (entries[recno].is_ads)
                            continue;
                        if (BuildPath(recno, path, sizeof(path))) {

                            printf("%lu|%llu|%llu|%llu|%llu|%lu|%s|%s|%s\n",
                                (unsigned long)recno,
                                (unsigned long long)entries[recno].frn,
                                (unsigned long long)entries[recno].parent_frn,
                                (unsigned long long)entries[recno].modification_time,
                                (unsigned long long)entries[recno].creation_time,
                                entries[recno].file_attribs,
                                entries[recno].is_dir ? "[DIR]" : "[FILE]",
                                entries[recno].name,
                                path);
                        }
                    }
                }

                // cleanup

                for (uint32_t i = 0; i < entry_capacity; i++) {
                    free(entries[i].dir_path_cache);
                    free(entries[i].name);
                }
                free(entries);
                for (uint32_t i = 0; i < link_count; i++) {
                    free(links[i].name);
                }
                free(links);
                free(buf);
            }
            break;
        }

        attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
        
    }
    
    CloseHandle(h);
    return 0;
    
    cleanup:
        if (buf) free(buf);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }

        return ret;
}

uint64_t EpochToNtfs(time_t epoch) {
    return ((uint64_t)epoch * TICKS_PER_SECOND) + TICKS_BTWN_1601_1970;
}

uint64_t ParseDatetimeToNtfs(const char *input) {
    int year, month, day, hour, min, sec;

    if (sscanf(input, "%d-%d-%d %d:%d:%d",
               &year, &month, &day,
               &hour, &min, &sec) != 6) {
        return 0; // invalid
    }

    struct tm t = {0};

    t.tm_year = year - 1900;
    t.tm_mon  = month - 1;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min  = min;
    t.tm_sec  = sec;
    t.tm_isdst = -1;

    time_t epoch = mktime(&t);

    if (epoch == (time_t)-1)
        return 0;

    return EpochToNtfs(epoch);
}
    
time_t NtfsToEpoch(uint64_t ntfs) {
    return (time_t)((ntfs - 116444736000000000ULL) / 10000000ULL);
}

void FormatFileTime(uint64_t ft, char *out, size_t outSize) {
    // FILETIME → Unix epoch (seconds + remainder)
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;

    if (ft < EPOCH_DIFF) {
        snprintf(out, outSize, "0");
        return;
    }

    uint64_t unix_100ns = ft - EPOCH_DIFF;

    time_t seconds = (time_t)(unix_100ns / 10000000ULL);
    uint64_t remainder = unix_100ns % 10000000ULL; // 100ns units

    struct tm tm;
    gmtime_s(&tm, &seconds);

    // convert remainder to nanoseconds
    uint64_t nanoseconds = remainder * 100ULL;

    snprintf(out, outSize,
        "%04d-%02d-%02d %02d:%02d:%02d.%09llu",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        (unsigned long long)nanoseconds);
}
