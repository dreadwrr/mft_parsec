#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <wchar.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "parsec.h"

#define TICKS_PER_SECOND 10000000ULL  // 100ns tick
#define TICKS_BTWN_1601_1970 116444736000000000ULL
// #define OUTBUF_SIZE (1024 * 1024) // 1MB
#define OUTBUF_SIZE (4 << 20)

LinkEntry *links = NULL;
uint32_t link_count = 0;
uint32_t link_capacity = 0;
FileEntry *entries = NULL;
uint32_t entry_capacity = 0;
uint32_t entry_count = 0;
uint32_t max_count = 0;
ExtEntry *ext = NULL;
uint32_t ext_capacity = 0;
uint32_t ext_count = 0;

// static const uint64_t FRN_RECORD_MASK = 0x0000FFFFFFFFFFFFULL;

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
        fprintf(stderr, "link capacity realloc failed\n");
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
            fprintf(stderr, "ensure capacity overflow\n");
            exit(1);
        }
        new_capacity *= 2;
    }

    FileEntry *new_entries = (FileEntry *)realloc(entries, new_capacity * sizeof(FileEntry));
    if (!new_entries) {
        fprintf(stderr, "ensure capacity realloc failed\n");
        exit(1);
    }

    memset(new_entries + entry_capacity, 0,
           (new_capacity - entry_capacity) * sizeof(FileEntry));

    entries = new_entries;
    entry_capacity = new_capacity;
}

void EnsureExtCapacity(void) {
    if (ext_count < ext_capacity)
        return;
    uint32_t new_capacity = ext_capacity ? ext_capacity * 2 : 1024;
    ExtEntry *new_ext = realloc(ext, new_capacity * sizeof(ExtEntry));
    if (!new_ext) {
        fprintf(stderr, "ext capacity realloc failed\n");
        exit(1);
    }
    ext = new_ext;
    ext_capacity = new_capacity;
}

void AppendLink(uint32_t recno, uint64_t frn, uint64_t parent_frn, const char *name) {
    EnsureLinkCapacity();
    links[link_count].recno = recno;
    links[link_count].frn = frn;
    links[link_count].parent_frn = parent_frn;
    links[link_count].name = _strdup(name);
    links[link_count].name_len = (uint16_t)strlen(name);
    if (!links[link_count].name) {
        fprintf(stderr, "strdup failed\n");
        exit(1);
    }
    link_count++;
}

void AppendExtension(uint32_t recno, uint32_t base_recno, uint64_t frn, uint64_t parent_frn, const char *name) {
    EnsureExtCapacity();
    ext[ext_count].recno = recno;
    ext[ext_count].base_recno = base_recno;
    ext[ext_count].frn = frn;
    ext[ext_count].parent_frn = parent_frn;
    ext[ext_count].name = _strdup(name);
    ext[ext_count].name_len = (uint16_t)strlen(name);
    if (!ext[ext_count].name) {
        fprintf(stderr, "strdup failed\n");
        exit(1);
    }
    ext_count++;
}

void ProcessRecord(unsigned char *buf, uint16_t bytesPerSector, uint32_t recno, uint32_t record_size, bool add_deleted) {

    FILE_RECORD_HEADER *hrec;  // added 05/09/2026
    hrec = (FILE_RECORD_HEADER *)buf;
    uint8_t in_use = 0;
    in_use = (hrec->flags & 0x0001) ? 1 : 0;
    // for --inuse flag return early
    if (!add_deleted && !in_use) {
        return;
    }

    ATTR_HEADER *attr;

    uint64_t frn = 0;    
    uint32_t file_attribs = 0;
    uint64_t usn = 0;
    uint64_t creation_time = 0;
    uint64_t modification_time = 0;
    uint64_t mft_modification_time = 0;
    uint64_t access_time = 0;
    // uint8_t is_reparse = 0;

    char names[16][1024] = {0};
    uint64_t parent_frns[16] = {0};
    int name_count = 0;

    uint8_t got_name = 0;

    char best_name[1024] = {0};
    uint16_t best_name_len = 0;

    uint64_t best_parent_frn = 0;

    char name[1024] = {0};
    uint64_t size = 0;

    uint8_t is_dir = 0;
    uint8_t has_ads = 0;

    // hrec = (FILE_RECORD_HEADER *)buf;  // original spot before add_deleted flag  // added 05/09/2026
    if (hrec->first_attr_offset >= record_size)
        return;

    if (memcmp(hrec->signature, "FILE", 4) != 0)  // sanity check is there a header
        return;

    if (!apply_usa(buf, bytesPerSector)) // apply fixups
        return;

    // only in_use if forensic level not needed
    // if (!(hrec->flags & 0x0001))
        // return;

    // in_use = (hrec->flags & 0x0001) ? 1 : 0;  // original spot before add_deleted flag  // added 05/09/2026

    is_dir = (hrec->flags & 0x0002) ? 1 : 0;

    // extension record
    if (hrec->base_record != 0) {
        frn = hrec->base_record;
    // base record
    } else {
        frn = ((uint64_t)hrec->sequence_number << 48) | hrec->record_number;  // frn = ((uint64_t)hrec->sequence_num << 48) | recno;  // original. inferred
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
            RESIDENT_ATTR_HEADER *res = (RESIDENT_ATTR_HEADER *)attr;  // not used originally. updated to use value_offset <--
            // (STANDARD_INFORMATION_ATTR *)attr; // this was original see parsec.h ln 59
            STANDARD_INFORMATION_ATTR *si = (STANDARD_INFORMATION_ATTR *)((uint8_t *)attr + res->value_offset);  
            file_attribs = si->file_attributes;
            creation_time = si->creation_time;
            modification_time = si->modification_time;
            mft_modification_time = si->mft_modification_time;
            access_time = si->access_time;
            usn = si->usn;
            // is_reparse = (si->file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;
        }

        if (attr->type == 0x30 && attr->non_resident == 0) {
            RESIDENT_ATTR_HEADER *res = (RESIDENT_ATTR_HEADER *)attr;  // not used originally. updated to use value_offset <--
            // FILE_NAME_ATTR *fn = (FILE_NAME_ATTR *)attr; // this was original see parsec.h ln 75
            FILE_NAME_ATTR *fn = (FILE_NAME_ATTR *)((uint8_t *)attr + res->value_offset);

            // some records may not have a usable name (only dos) in base record. store parent frn and get name after finishing from ExtEntry

            if (!best_parent_frn)
                best_parent_frn = fn->parent_ref;
            
            // prefer Windows or Windows&Dos
            if (fn->name_type != 2 && fn->name_length < 512 && name_count < 16) {

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
                    // detect truncation
                    // continue;
                // }

                size_t name_len = (size_t)(len - 1);
                if (name_len >= sizeof(best_name)) {
                    attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
                    continue;
                }

                // Base record store first name as canonical
                if (!got_name) {
                    
                    memcpy(best_name, name, name_len + 1);
                    best_name_len = (uint16_t)name_len;
                    best_parent_frn = fn->parent_ref;
                    got_name = 1;
                } 
                
                // store others as links even though above is technically a link
                else {
                    memcpy(names[name_count], name, name_len + 1);
                    parent_frns[name_count] = fn->parent_ref;
                    name_count++;
                }
            }
        }

        if (attr->type == 0x80) {
            if (attr->name_length != 0) {
                // skip ADS
                has_ads = 1;
                attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
                continue;
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

    if (hrec->base_record == 0) {

        EnsureEntryCapacity(recno);
        max_count = recno;
        entry_count++;

        entries[recno].frn = frn;
        entries[recno].parent_frn = best_parent_frn;
        entries[recno].record_number = hrec->record_number;
        entries[recno].sequence_num = hrec->sequence_number;
        //
        // uint64_t parent_recno = best_parent_frn & FRN_RECORD_MASK;
        // entries[recno].parent_sequence_num = (uint16_t)(best_parent_frn >> 48);
        //
        entries[recno].record_offset = hrec->record_number * record_size;  // for --target diagnostics mode

        entries[recno].name = _strdup(best_name);
        entries[recno].name_len = best_name_len;

        entries[recno].size = size;

        entries[recno].in_use = in_use;
        // entries[recno].in_use = 1;

        entries[recno].is_dir = is_dir;
        entries[recno].has_ads = has_ads;
        entries[recno].hard_link_count = hrec->hard_link_count;
        entries[recno].file_attribs = file_attribs;

        entries[recno].usn = usn;
        entries[recno].creation_time = creation_time;
        entries[recno].modification_time = modification_time;
        entries[recno].mft_modification_time = mft_modification_time;
        entries[recno].access_time = access_time;
        // entries[recno].is_reparse = is_reparse;

        entries[recno].link_index = link_count;
        entries[recno].link_count = name_count;
        
        // only save whatever hardlinks fit in base record
        if (in_use) {
            for (int i = 0; i < name_count; i++) {
                AppendLink(
                    (uint32_t)(frn & FRN_RECORD_MASK),
                    frn,
                    parent_frns[i],
                    names[i]
                );
            }
        }
    // extension record
    } else {
        if (got_name) {
            AppendExtension(
                recno,
                (uint32_t)(frn & FRN_RECORD_MASK),
                frn,
                best_parent_frn,
                best_name
            );
        }
    }
}

/* Read saved mft */

uint32_t ReadRun(HANDLE h, uint64_t runBytes, uint16_t bytesPerSector, uint32_t startRecno, uint32_t record_size) {
    // read the saved mft in one run
    uint32_t processed = 0;
    uint64_t remaining = runBytes;
    uint64_t offset = 0;
    bool deleted = true;
    unsigned char *buffer = malloc((size_t)CHUNK_SIZE);
    if (!buffer) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    while (remaining > 0) {
        uint64_t chunk = remaining > CHUNK_SIZE ? CHUNK_SIZE : remaining;
        uint64_t records = chunk / record_size;

        Read(h, buffer, offset, (DWORD)chunk);

        for (uint64_t i = 0; i < records; i++) {
            ProcessRecord(buffer + (i * record_size), bytesPerSector, startRecno + (uint32_t)i, record_size, deleted);
            processed++;
        }

        startRecno += (uint32_t)records;
        offset += chunk;
        remaining -= chunk;
    }

    free(buffer);
    return processed;
}

uint64_t ReadAttributes(HANDLE h, unsigned char *buf, uint32_t record_size, FILE_RECORD_HEADER *hrec, uint16_t bytesPerSector) {
    // first read mft dump header to read the saved mft
    ATTR_HEADER *attr = (ATTR_HEADER *)(buf + hrec->first_attr_offset);

    while ((unsigned char *)attr < buf + record_size) {
        if (attr->type == 0xFFFFFFFF) {
            break;
        }

        if (attr->length == 0) {
            break;
        }
        // printf("Attr type: 0x%08x len=%u\n", attr->type, attr->length); // debug
        if (attr->type == 0x80) {
            if (!attr->non_resident) {
                fprintf(stderr, "$DATA is resident\n");
                return 0;
            } else {

                NONRES_ATTR_HEADER *ndata = (NONRES_ATTR_HEADER *)attr;

                uint64_t mft_size = ndata->real_size;
                uint64_t record_count = mft_size / record_size;

                ReadRun(h, mft_size, bytesPerSector, 0, record_size);

                return record_count;

            }
            break;
        }

        attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
    }
    
    return 0;
}
/* end Read saved mft */

/* Write mft*/

uint32_t RunWrite(HANDLE h, HANDLE o, uint64_t lcn, uint64_t clusters, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t startRecno, uint32_t record_size) {
    // write
    // printf("RunWrite lcn=%llu clusters=%llu\n", (unsigned long long)lcn, (unsigned long long)clusters);
    uint32_t processed = 0;
    uint64_t runBytes = clusters * bytesPerCluster;
    uint64_t offset = lcn * bytesPerCluster;

    unsigned char *buffer = malloc((size_t)CHUNK_SIZE);
    if (!buffer) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }

    while (runBytes > 0) {
        uint64_t chunk = runBytes > CHUNK_SIZE ? CHUNK_SIZE : runBytes;
        uint64_t records = chunk / record_size;

        Read(h, buffer, offset, (DWORD)chunk);
        DWORD written;
        WriteFile(o, buffer, (DWORD)chunk, &written, NULL);

        processed += (uint32_t)records;
        offset += chunk;
        runBytes -= chunk;
    }

    free(buffer);
    return processed;
}


void WriteRuns(HANDLE h, HANDLE o, unsigned char *run, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t record_size) {
    // write the mft runs
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

        uint32_t processed = RunWrite(h, o, currentLCN, runLength, bytesPerCluster, bytesPerSector, currentRecno, record_size);

        currentRecno += processed;
        run_number++;

    }
}

uint64_t WriteAttributes(HANDLE h, HANDLE o, unsigned char *buf, uint32_t record_size, FILE_RECORD_HEADER *hrec, uint64_t bytesPerCluster, uint16_t bytesPerSector) {
    // read mft header then call WriteRuns 
    ATTR_HEADER *attr = (ATTR_HEADER *)(buf + hrec->first_attr_offset);

    while ((unsigned char *)attr < buf + record_size) {
        if (attr->type == 0xFFFFFFFF) {
            break;
        }

        if (attr->length == 0) {
            break;
        }
        // printf("Attr type: 0x%08x len=%u\n", attr->type, attr->length); // debug
        if (attr->type == 0x80) {
            if (!attr->non_resident) {
                printf("$DATA is resident\n");
                return 0;
            } else {

                NONRES_ATTR_HEADER *ndata = (NONRES_ATTR_HEADER *)attr;

                uint64_t mft_size = ndata->real_size;
                uint64_t record_count = mft_size / record_size;

                unsigned char *run = (unsigned char *)attr + ndata->run_offset;

                WriteRuns(h, o, run, bytesPerCluster, bytesPerSector, record_size);

                return record_count;

            }
            break;
        }

        attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
    }
    
    return 0;
}
/* end Write mft */

/* Regular */

uint32_t ProcessRun(HANDLE h, uint64_t lcn, uint64_t clusters, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t startRecno, uint32_t record_size, bool deleted) {
    
    uint32_t processed = 0;
    uint64_t runBytes = clusters * bytesPerCluster;
    uint64_t offset = lcn * bytesPerCluster;
    
    unsigned char *buffer = malloc((size_t)CHUNK_SIZE);
    if (!buffer) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    
    while (runBytes > 0) {
        uint64_t chunk = runBytes > CHUNK_SIZE ? CHUNK_SIZE : runBytes;
        uint64_t records = chunk / record_size;

        Read(h, buffer, offset, (DWORD)chunk);

        for (uint64_t i = 0; i < records; i++) {
            ProcessRecord(buffer + (i * record_size), bytesPerSector, startRecno + (uint32_t)i, record_size, deleted);
            processed++;
        }

        startRecno += (uint32_t)records;
        offset += chunk;
        runBytes -= chunk;
    }

    free(buffer);
    return processed;
}


void ParseRuns(HANDLE h, unsigned char *run, uint64_t bytesPerCluster, uint16_t bytesPerSector, uint32_t record_size, bool deleted, bool has_target) {

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

        uint32_t processed = ProcessRun(h, currentLCN, runLength, bytesPerCluster, bytesPerSector, currentRecno, record_size, deleted);
        currentRecno += processed;
        // currentRecno += (uint32_t)((runLength * bytesPerCluster) / record_size);  // original
        
        run_number++;
        
        // mft run data for run_number
        // printf("Run %d: LCN=%lld clusters=%llu byte_offset=%llu bytes=%llu\n", x, (long long)currentLCN,
            // (unsigned long long)runLength, (unsigned long long)(currentLCN * bytesPerCluster),
            // (unsigned long long)(runLength * bytesPerCluster));

        // debug
        uint64_t runBytes = runLength * bytesPerCluster;
        if (runBytes % record_size != 0)
            fprintf(stderr, "warning: run not aligned to record size\n");
    }
}
/* end Regular start ln 175 */

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

    // files use parent directory, dirs use themselves
    if (!entries[orig_recno].is_dir) {
        uint64_t parent_frn = entries[orig_recno].parent_frn;
        uint32_t parent_recno = (uint32_t)(parent_frn & FRN_RECORD_MASK);
        uint16_t parent_seq = (uint16_t)(parent_frn >> 48);

        if (parent_recno >= entry_capacity)
            return 0;
        // if ((uint16_t)(entries[parent_recno].frn >> 48) != parent_seq)
            // return 0;
        if (entries[parent_recno].sequence_num != parent_seq)
            return 0;
        recno = parent_recno;
    }

    uint32_t target_recno = recno;

    if (entries[recno].dir_path_ready && entries[recno].dir_path) {
        strncpy(out, entries[recno].dir_path, outSize - 1);
        out[outSize - 1] = '\0';
        return 1;
    }
    
    while (1) {
        if (recno >= entry_capacity)
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
        uint32_t parent_recno = (uint32_t)(parent_frn & FRN_RECORD_MASK);
        uint16_t parent_seq = (uint16_t)(parent_frn >> 48);

        if (parent_recno == recno)
            return 0;
        if (parent_recno >= entry_capacity)
            return 0;
        if (entries[parent_recno].sequence_num != parent_seq)
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

        if (pos + len >= outSize)
            return 0;

        memcpy(out + pos, name, len);
        pos += len;
        out[pos] = '\0';
    }

    if (pos == 0) {
        if (outSize < 2)
            return 0;
        memcpy(out, "\\", 2);
    }

    char *tmp = _strdup(out);
    if (!tmp) 
        return 0;
    // its a dir cache and save the path
    free(entries[target_recno].dir_path);
    entries[target_recno].dir_path = tmp;
    entries[target_recno].dir_path_ready = 1;

    // its a file save its path
    if (orig_recno != target_recno) {
        tmp = _strdup(out);
        if (!tmp)
            return 0;
        free(entries[orig_recno].dir_path);
        entries[orig_recno].dir_path = tmp;
        entries[orig_recno].dir_path_ready = 1;
    }

    return 1;
}

int BuildPath(uint32_t recno, const char *name, uint16_t name_len, char *out, size_t outSize) {
    char dir[MAX_PTH];

    size_t pos;

    if (!out || outSize == 0)
        return 0;

    out[0] = '\0';

    if (recno >= entry_capacity)
        return 0;
    // can only be root record 5
    if (strcmp(name, ".") == 0) {
        if (outSize < 2)
            return 0;
        strncpy(out, "\\", outSize - 1);
        out[outSize - 1] = '\0';
        return 1;
    }

    // initially build the dir path
    if (!BuildDirPath(recno, dir, sizeof(dir)))
        return 0;

    // if failure as in no name or otherwise return path so can be debugged
    strncpy(out, dir, outSize - 1);
    out[outSize - 1] = '\0';
    
    // direcory just uses parent path finish early

    if (entries[recno].is_dir || !name || name[0] == '\0') {
        return 1;
    }

    // files uses full path
    // build the file path

    pos = strlen(out);

    // empty path is one \\.
    if (pos == 0) {
        if (outSize < 2)
            return 0;
        memcpy(out, "\\", 2);
        pos = 1;
    }

    // join filename

    if (pos > 1) {
        if (pos + 1 >= outSize)
            return 0;
        out[pos++] = '\\';
        out[pos] = '\0';
    }

    if (pos + name_len >= outSize)
        return 0;

    memcpy(out + pos, name, name_len);
    pos += name_len;
    out[pos] = '\0';

    return 1;
}

uint64_t ParseAttributes(HANDLE h, unsigned char *buf, uint32_t record_size, FILE_RECORD_HEADER *hrec, uint64_t bytesPerCluster, uint16_t bytesPerSector, bool deleted, bool has_target) {
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
                fprintf(stderr, "$DATA is resident\n");
                return 0;
            } else {

                NONRES_ATTR_HEADER *ndata = (NONRES_ATTR_HEADER *)attr;

                uint64_t mft_size = ndata->real_size;
                uint64_t record_count = mft_size / record_size;
                
                // if (has_target) {
                    // printf("[RECORD]  : %llu\n", (unsigned long long)record_count);  // for progress indicating
                // }

                if (has_target) {
                    printf("$DATA is non-resident\n");
                    printf("run offset   : %u\n", ndata->run_offset);
                    printf("alloc size   : %llu\n", (unsigned long long)ndata->alloc_size);
                    printf("real size    : %llu\n", (unsigned long long)mft_size);
                    printf("init size    : %llu\n", (unsigned long long)ndata->initialized_size);
                }

                unsigned char *run = (unsigned char *)attr + ndata->run_offset;

                ParseRuns(h, run, bytesPerCluster, bytesPerSector, record_size, deleted, has_target);

                // parsing complete output area
                return record_count;

            }
            break;
        }

        attr = (ATTR_HEADER *)((unsigned char *)attr + attr->length);
    }
    
    return 0;
}

int is_file(const char *path) {
    DWORD attrs = GetFileAttributes(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;
    } else if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        return 0;
    }
    return 1;
}

void Help(char* argv[]) {
    printf("MFT parsec \n\n\
    optional drive (default C:) \n\
    parsec.exe \n\
    parsec.exe S: \n\n\
    save mft to file \n\
    --output <mft raw> \n\
    note: above argument cannot be used with options below \n\n\
    with no argument output all entries from the MFT to stdout in csv fmt \n\
    for timestamps use --csv flag. also --inuse can be used for active records only \n\n\
    to read mft from file relative or absolute\n\
    --file <mft file> \n\n\
    and can take 1 argument: \n\n\
    search for files by cutoff\n\
    --cutoff \"2026-03-19 10:13:18\" or 2026-03-19T10:13:18\n\n\
    diagnostics list mft record\n\
    --target <record number> or <frn>\n\n");
    exit(0);
}

/**
05/10/2026

usage:

optional drive (default C:)
./parsec.exe
or
./parsec.exe S:
./parsec.exe C: --cutoff "2026-03-19 10:13:18"
or
./parsec.exe --csv

dump drive mft to file
--output <target>

above argument cannot be used with other options

main output is with with no argument output all valid file entries from the MFT to stdout csv format.
Note: the format is parser friendly and can be hard to read. use --csv for readable timestamps ect.
in addition --inuse can limit console writes and save time for regular mode.


read saved mft relative or absolute
--file <raw mft>

and also can take 1 argument

search for files by cutoff by system time
--cutoff "2026-03-19 10:13:18" or 2026-03-19T10:13:18

diagnostics list mft record
--target <record number> or <frn>

*/
int main(int argc, char *argv[]) {

    // printf("sizeof(FileEntry) = %zu\n", sizeof(FileEntry));
    // exit(0);

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        Help(argv);
    }

    setvbuf(stdout, NULL, _IOFBF, 4 << 20);  // enable buffering
    
    HANDLE o;
    char *drive = "C:";  // default
    char drive_buf[3];
    int ret = 1;  // assume error
    int arg_index = 1;

    size_t str_len = 0;

    const char *input = NULL;
    
    bool flag_set = false;  // if should stop parsing args

    if (argc >= 2) {
        str_len = strlen(argv[1]);

        if (str_len > 1 && str_len <= 3 &&
            isalpha((unsigned char) argv[1][0]) &&
            argv[1][1] == ':') {

            drive_buf[0] = argv[1][0];
            drive_buf[1] = ':';
            drive_buf[2] = '\0';

            drive = drive_buf;
            arg_index = 2;  // shift
        } else if (strcmp(argv[1], "--file") == 0) {
            if (argc <= arg_index + 1) {
                printf("--file no source file specified\n");
                return 0;
            }

            input = argv[arg_index + 1];
            if (!is_file(input)) {
                printf("target input not a file: %s", input);
                exit(0);
            }
            flag_set = true;

            arg_index = 3; // shift
        }
    }

    char volume[16];  // set target drive ie C: S: E:

    snprintf(volume, sizeof(volume), "\\\\.\\%s", drive);  // const char *volume = "\\\\.\\C:";  // original design moved to drive arg

    uint64_t cutoff_time = 0;

    uint64_t target_recno = 0;
    bool has_target = false;

    bool deleted = true;  // default is to show all records

    bool csv = false;  // alternative output

    // read any drive and or one optional argument

    const char *output = NULL;  // save or dump mode

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
            // or
            // snprintf(arg_buf, sizeof(arg_buf), "%s", argv[arg_index + 1]);

            t = strchr(arg_buf, 'T');
            if (t) {
                *t = ' ';
            }

            cutoff_time = ParseDatetimeToNtfs(arg_buf);  // const char *input = argv[1]; original prototype for sscanf using ParseDatetimeToNtfs
            if (cutoff_time == 0) {
                printf("Invalid datetime format 2026-03-19T10:13:18 or \"2026-03-19 10:13:18\" \n");
                return 1;
            }
            flag_set = true;

        } else if (strcmp(argv[arg_index], "--target") == 0) {
            if (argc <= arg_index + 1) {
                printf("--target requires a record number\n");
                return 1;
            }
            errno = 0;
            unsigned long long val = strtoull(argv[arg_index + 1], &t, 10);
            if (*t != '\0' || errno == ERANGE) {
                printf("Invalid target %s\n", argv[arg_index + 1]);
                return 1;
            }

            target_recno = (uint64_t)val;
            has_target = true;
            flag_set = true;

        } else if (!input && strcmp(argv[arg_index], "--output") == 0) {

            // strncpy(arg_buf, argv[arg_index + 1], sizeof(arg_buf) - 1);
            // arg_buf[sizeof(arg_buf) - 1] = '\0';
            // printf("%s", arg_buf);

            output = argv[arg_index + 1];
            o = CreateFileA(
                output,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (o == INVALID_HANDLE_VALUE) {
                printf("Failed to open output file: %s\n", output);
                exit(0);
            }
            flag_set = true;

        // for regular use alternate output
        } else if (strcmp(argv[arg_index], "--csv") == 0) {
            csv = true;
            // for (int i = 1; i < argc; i++) {
                // if (strcmp(argv[i], "--csv") == 0) {
                    // csv = true;
                // }
            // }
          arg_index++;
        
        // check for invalid
        } else if (!strcmp(argv[arg_index], "--inuse") == 0) {
            printf("Unknown option %s\n", argv[arg_index]);
            return 1;
        }
        
        // the --inuse flag was added in and for regular use only
        // can save time by limiting console writes. Also later in python list iterating with a smaller list
        // can be used with --csv

        if (argc > arg_index && !flag_set) {
            if (strcmp(argv[arg_index], "--inuse") == 0) {
                deleted = false;  // limit uneccessary parsing\\stdout
            }
        }
    }

    // #ifdef _WIN32
    // if (qt_output) {
        // _setmode(_fileno(stdout), _O_BINARY);
    // }
    // #endif

    // original design
    // const uint64_t mft_offset = 0xC0000000ULL; // used fsutil fsinfo ntfsinfo C: for starting cluster.
    // const DWORD record_size = 1024;  // assumed same as 512 for sector
    // unsigned char buf[1024];

    HANDLE h;
    unsigned char *buf = NULL;

    DWORD bytes_read = 0;

    FILE_RECORD_HEADER *hrec;

    const char *target = input ? input : volume;

    h = CreateFileA(
        target,
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

    uint32_t record_size = 1024;
    uint16_t bytesPerSector = 0;
    uint64_t bytesPerCluster = 0;
    uint64_t mftOffset = 0;
    // these are listed below in has_target debug mode

    BootSector bootsector;

    if (!input) {
        Read(h, &bootsector, 0, sizeof(bootsector));
        /* verify drive */
        if (bootsector.bootSignature != 0xAA55) {
            fprintf(stderr, "Invalid boot sector signature\n");
            goto cleanup;
        }
        if (memcmp(bootsector.name, "NTFS    ", 8) != 0) {
            fprintf(stderr, "Not an NTFS volume\n");
            goto cleanup;
        }
        
        record_size = GetFileRecordSize(&bootsector);
        bytesPerSector = bootsector.bytesPerSector;
        bytesPerCluster = (uint64_t)bootsector.bytesPerSector * bootsector.sectorsPerCluster;
        mftOffset = bootsector.mftStart * bytesPerCluster;
    }

    buf = malloc(record_size);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    // record 0
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

    if (input) {
        record_size = hrec->allocated_size;
        bytesPerSector = record_size / (hrec->usa_count - 1);
    }

    if (!apply_usa(buf, bytesPerSector)) {
        fprintf(stderr, "USA fixup failed\n");
        goto cleanup;
    }

    if (memcmp(hrec->signature, "FILE", 4) != 0) {
        fprintf(stderr, "Invalid MFT record signature (expected FILE)\n");
        goto cleanup;
    } // } else {
        // printf("Looks like a FILE record\n");  // success
    // }

    uint64_t record_count = 0;

    // write mft
    if (output) {
        WriteAttributes(h, o, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector);
        free_processed(buf);
        CloseHandle(o);
        CloseHandle(h);
        exit(0);
        
    // normal mft parse
    } else if (!input) {
        record_count = ParseAttributes(h, buf, record_size, hrec, bytesPerCluster, bootsector.bytesPerSector, deleted, has_target);
        
    // read saved mft
    } else if (input) {
        record_count = ReadAttributes(h, buf, record_size, hrec, bytesPerSector);
    }

    // parsing complete

    /* output area */

    if (record_count) {
       
        char path[MAX_PTH];


        // check extension records for over flows ie name missing <--
        for (uint32_t i = 0; i < ext_count; i++) {
            uint32_t b = ext[i].base_recno;

            if (entries[b].in_use && (entries[b].name == NULL || entries[b].name[0] == '\0') && entries[b].frn == ext[i].frn) {
                free(entries[b].name);
                entries[b].name = _strdup(ext[i].name);
                entries[b].name_len = ext[i].name_len;
                entries[b].parent_frn = ext[i].parent_frn;
            }
        }

        uint32_t attrs = 0;
        uint64_t parent_recno = 0;
        uint16_t parent_seq = 0;

        /* print mft entries for run */
        if (cutoff_time == 0 && !has_target) {
            
            /* regular output format */
            if (!csv) {
                printf("recno,sequence,parent_recno,parent_sequence,in_use,size,hard_link_count,modification_time,creation_time,mft_modified,access_time,file_attribs,type,has_ads,name,path\n");
                
                for (uint32_t recno = 0; recno < max_count + 1; recno++) {
                    if (!deleted && !entries[recno].in_use)
                        continue;
                    if (!entries[recno].name)
                        continue;

                    if (BuildPath(recno, entries[recno].name, entries[recno].name_len, path, sizeof(path))) {

                        parent_recno = entries[recno].parent_frn & FRN_RECORD_MASK;
                        parent_seq = (uint16_t)(entries[recno].parent_frn >> 48);

                        printf("%lu,%hu,%llu,%hu,%d,%llu,%hu,%llu,%llu,%llu,%llu,%lu,%s,%d,\"%s\",\"%s\"\n",
                            (unsigned long)recno,
                            entries[recno].sequence_num,
                            (unsigned long long)parent_recno,
                            parent_seq,
                            (int) entries[recno].in_use,
                            (unsigned long long)entries[recno].size,
                            entries[recno].hard_link_count,
                            (unsigned long long)entries[recno].modification_time,
                            (unsigned long long)entries[recno].creation_time,
                            (unsigned long long)entries[recno].mft_modification_time,
                            (unsigned long long)entries[recno].access_time,
                            (unsigned long)entries[recno].file_attribs,
                            entries[recno].is_dir ? "[DIR]" : "[FILE]",
                            (int) entries[recno].has_ads,
                            entries[recno].name,
                            path);

                        // print all hardlinks
                        for (uint32_t i = 0; i < entries[recno].link_count; i++) {
                            LinkEntry *lnk = &links[entries[recno].link_index + i];
                            if (BuildPath(lnk->recno, lnk->name, lnk->name_len, path, sizeof(path))) {

                                parent_recno = (uint32_t)(entries[recno].parent_frn & FRN_RECORD_MASK);
                                parent_seq = (uint16_t)(entries[recno].parent_frn >> 48);
                                printf("%lu,%hu,%llu,%hu,%d,%llu,%hu,%llu,%llu,%llu,%llu,%lu,%s,%d,\"%s\",\"%s\"\n",
                                    (unsigned long)lnk->recno,
                                    entries[recno].sequence_num,
                                    (unsigned long long)parent_recno,
                                    parent_seq,
                                    (int) entries[recno].in_use,
                                    (unsigned long long)entries[recno].size,
                                    entries[recno].hard_link_count,
                                    (unsigned long long)entries[recno].modification_time,
                                    (unsigned long long)entries[recno].creation_time,
                                    (unsigned long long)entries[recno].mft_modification_time,
                                    (unsigned long long)entries[recno].access_time,
                                    (unsigned long)entries[recno].file_attribs,
                                    "[HLINK]",
                                    (int) entries[recno].has_ads,
                                    lnk->name,
                                    path);
                            }
                        }
                    } 
                }

                ret = 0;
                
            /* write different format than default */
            } else {
                char mt[64], ct[64], mft[64], at[64];

                printf("recno,sequence,parent_recno,parent_sequence,in_use,size,hard_link_count,modification_time,creation_time,mft_modified,access_time,file_attribs,type,has_ads,name,path\n");

                for (uint32_t recno = 0; recno < max_count + 1; recno++) {
                    if (!entries[recno].name)
                        continue;
                    if (!deleted && !entries[recno].in_use)
                        continue;

                    if (BuildPath(recno, entries[recno].name, entries[recno].name_len, path, sizeof(path))) {

                        parent_recno = entries[recno].parent_frn & FRN_RECORD_MASK;
                        parent_seq = (uint16_t)(entries[recno].parent_frn >> 48);

                        FormatFileTime(entries[recno].modification_time, mt, sizeof(mt));
                        FormatFileTime(entries[recno].creation_time, ct, sizeof(ct));
                        FormatFileTime(entries[recno].mft_modification_time, mft, sizeof(mft));
                        FormatFileTime(entries[recno].access_time, at, sizeof(at));

                        attrs = entries[recno].file_attribs;
                        // printf("attrs=0x%08X\n", attrs);
                        // printf("%lu", (unsigned long)entries[recno].file_attribs);

                        printf("%lu,%hu,%llu,%hu,%d,%llu,%hu,%s,%s,%s,%s,0x%08X,%s,%d,\"%s\",\"%s\"\n",
                            (unsigned long)recno,
                            entries[recno].sequence_num,
                            (unsigned long long)parent_recno,
                            parent_seq,
                            (int) entries[recno].in_use,
                            (unsigned long long)entries[recno].size,
                            entries[recno].hard_link_count,
                            mt,
                            ct,
                            mft,
                            at,
                            attrs,
                            entries[recno].is_dir ? "[DIR]" : "[FILE]",
                            (int) entries[recno].has_ads,
                            entries[recno].name,
                            path);

                        // print all hardlinks
                        for (uint32_t i = 0; i < entries[recno].link_count; i++) {
                            LinkEntry *lnk = &links[entries[recno].link_index + i];
                            if (BuildPath(lnk->recno, lnk->name, lnk->name_len, path, sizeof(path))) {

                                printf("%lu,%hu,%llu,%hu,%d,%llu,%hu,%s,%s,%s,%s,0x%08X,%s,%d,\"%s\",\"%s\"\n",
                                    (unsigned long)lnk->recno,
                                    entries[recno].sequence_num,
                                    (unsigned long long)parent_recno,
                                    parent_seq,
                                    (int) entries[recno].in_use,
                                    (unsigned long long)entries[recno].size,
                                    entries[recno].hard_link_count,
                                    mt,
                                    ct,
                                    mft,
                                    at,
                                    attrs,
                                    "[HLINK]",
                                    (int) entries[recno].has_ads,
                                    lnk->name,
                                    path);
                            }
                        }
                    } 
                }
                ret = 0;
            }

        /* search by time */
        } else if (cutoff_time > 0) {

            for (uint32_t i = 0; i < max_count + 1; i++) {
                if (entries[i].is_dir)
                    continue;
                if (!entries[i].name)
                    continue;
                if (!entries[i].in_use)
                    continue;

                uint64_t mod_time = entries[i].modification_time;
                uint64_t creation_time = entries[i].creation_time;

                // verify cutoff_time matches from arg
                // printf("cutoff=%llu mod_time=%llu creation_time=%llu\n", (unsigned long long)cutoff_time, (unsigned long long)mod_time, (unsigned long long)creation_time);
 
                if (!(mod_time >= cutoff_time || creation_time >= cutoff_time))
                    continue;
                if (!(BuildPath(i, entries[i].name, entries[i].name_len, path, sizeof(path)))) {
                    continue;
                }
                if (input) {
                    drive = "";
                }
                printf("%s%s\n", drive, path);
                for (uint32_t j = 0; j < entries[i].link_count; j++) {
                    LinkEntry *lnk = &links[entries[i].link_index + j];
                    if (BuildPath(lnk->recno, lnk->name, lnk->name_len, path, sizeof(path))) {
                        printf("%s%s\n", drive, path);
                    }
                }
            }
            ret = 0;

        /* retrieve single record */
        } else if (has_target) {
    
            int is_frn = 0;
            uint16_t seq_no = 0;
            uint64_t recno = 0;

            // frn
            if (target_recno >= max_count) {
                recno = target_recno & FRN_RECORD_MASK;
                seq_no = (uint16_t)(target_recno >> 48);
                is_frn = 1;
            // or record number
            } else {
                recno = target_recno;
            }

            if (recno <= max_count) {
                FileEntry *e = &entries[recno];

                if (is_frn && e->sequence_num != seq_no) {
                    goto cleanup;
                }

                // if (!entries[i].in_use)
                    // continue;
                // if (!entries[i].name)
                    // continue;

                attrs = e->file_attribs;

                const char *ro   = (attrs & FILE_ATTRIBUTE_READONLY) ? " [READONLY]" : "";
                const char *hid  = (attrs & FILE_ATTRIBUTE_HIDDEN) ? " [HIDDEN]" : "";
                const char *sys  = (attrs & FILE_ATTRIBUTE_SYSTEM) ? " [SYSTEM]" : "";
                const char *arc  = (attrs & FILE_ATTRIBUTE_ARCHIVE) ? " [ARCHIVE]" : "";
                const char *rep  = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ? " [REPARSE]" : "";
                const char *spa = (attrs & FILE_ATTRIBUTE_SPARSE_FILE)    ? " [SPARSE]"  : "";
                const char *rec = (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN) ? " [RECALL]"  : "";
                const char *notc = (attrs & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) ? " [NOTINDEXED]" : "";
                printf("=== DEBUG RECORD %u ===\n", e->record_number);

                printf("flags=0x%08X%s%s%s%s%s%s%s\n",
                    attrs, ro, hid, sys, arc, rep, spa, rec);
                // printf("file_attributes=0x%08X\n", entries[i].file_attribs);

                printf("frn=%llu\n", (unsigned long long)e->frn);
                printf("parent_frn=%llu\n", (unsigned long long)e->parent_frn);
                
                printf("rec=%u\n", e->record_number);
                printf("seq=%u\n", e->sequence_num);

                parent_recno = e->parent_frn & FRN_RECORD_MASK;
                parent_seq = (uint16_t)(e->parent_frn >> 48);
                printf("parent_rec=%llu\n", parent_recno);
                printf("parent_seq=%u\n", parent_seq);

                printf("offset=%llu hex=0x%llx\n", 
                    (unsigned long long)e->record_offset,
                    (unsigned long long)e->record_offset);
                
                printf("name=%s\n", e->name ? e->name : "(null)");
                printf("size=%llu\n", e->size);
                printf("in_use=%u\n", e->in_use);
                printf("is_dir=%u\n", e->is_dir);
                printf("has_ads=%u\n", e->has_ads);

                printf("hard_links=%u\n", e->hard_link_count);

                char out[64];

                uint64_t times[4] = {
                    e->creation_time,
                    e->modification_time,
                    e->mft_modification_time,
                    e->access_time
                };

                const char *labels[4] = {
                    "ctime",
                    "mtime",
                    "mft modified",
                    "atime"
                };

                for (int t = 0; t < 4; t++) {
                    FormatFileTime(times[t], out, sizeof(out));
                    printf("%s=%s\n", labels[t], out);
                }

                printf("Last Usn=%llu\n", (unsigned long long)e->usn);

                if (e->name && BuildPath(e->record_number, e->name, e->name_len, path, sizeof(path))) {
                    printf("path=%s\n", path);
                } else {
                    printf("path=(failed)\n");
                }

                printf("========================\n");
                ret = 0;
            } else {
                if (is_frn) {
                    fprintf(stderr, "Invalid FRN %llu\n", (unsigned long long)target_recno);
                } else {
                    fprintf(stderr, "Invalid record %u\n", (uint32_t)target_recno);
                }
            }
        }
    }

    free_processed(buf);

    CloseHandle(h);
    return ret;

    cleanup:
        free_processed(buf);

        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }

        return 1;
}

uint64_t ntfs_to_epoch_us(uint64_t ntfs) {
    if (ntfs == 0)
        return 0;
    return (ntfs - 116444736000000000ULL) / 10ULL;
}

uint64_t EpochToNtfs(time_t epoch) {
    return ((uint64_t)epoch * TICKS_PER_SECOND) + TICKS_BTWN_1601_1970;
}

uint64_t ParseDatetimeToNtfs(const char *input) {
    int year, month, day, hour, min, sec;

    if (sscanf(input, "%d-%d-%d %d:%d:%d",
               &year, &month, &day,
               &hour, &min, &sec) != 6) {
        return 0;
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
    // epoch seconds
    return (time_t)((ntfs - TICKS_BTWN_1601_1970) / TICKS_PER_SECOND);
}

void FormatFileTime(uint64_t ft, char *out, size_t outSize) {
    // FILETIME Unix epoch (seconds + remainder)
    const uint64_t EPOCH_DIFF = TICKS_BTWN_1601_1970;

    if (ft < EPOCH_DIFF) {
        snprintf(out, outSize, "0");
        return;
    }

    uint64_t unix_100ns = ft - EPOCH_DIFF;

    time_t seconds = (time_t)(unix_100ns / TICKS_PER_SECOND);
    uint64_t remainder = unix_100ns % TICKS_PER_SECOND; // 100ns units

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

void free_processed(unsigned char *buff) {

    if (entries) {
        for (uint32_t i = 0; i < max_count + 1; i++) {
            free(entries[i].dir_path);
            free(entries[i].name);
        }
        free(entries);
        entries = NULL;
    }
    
    if (links) {
        for (uint32_t i = 0; i < link_count; i++) {
            free(links[i].name);
        }
        free(links);
        links = NULL;
    }
    
    if (ext) {
        for (uint32_t i = 0; i < ext_count; i++) {
            free(ext[i].name);
        }
        free(ext);
        ext = NULL;
    }

    free(buff);
    link_capacity = 0;
    entry_capacity = 0;
    ext_capacity = 0;
    link_count = 0;
    entry_count = 0;
    ext_count = 0;
    max_count = 0;
}
