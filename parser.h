#include <stdint.h>
#include <windows.h>
#include <stdbool.h>
#define MAX_NAME 1024
#define MAX_PTH 8192
#define CHUNK_SIZE (64ULL * 1024ULL * 1024ULL)  //  read mft in 64MB chunks
#define FRN_RECORD_MASK 0x0000FFFFFFFFFFFFULL
#define MFT_FILE_ATTRIBUTE_DIRECTORY 0x2000

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

// RESIDENT_ATTR_HEADER; // originally was first field below, see ln 244 parser.c
typedef struct {
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

// RESIDENT_ATTR_HEADER resident; // originally was first field below, see ln 257 parser.c
typedef struct {
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
    uint16_t sequence_num;
    uint64_t record_offset;
    char *name;
    uint16_t name_len;
    uint64_t size;
    char *dir_path;
    uint8_t dir_path_ready;
    uint8_t in_use;
    uint8_t is_dir;
    uint8_t has_ads;
    uint16_t hard_link_count;
    uint16_t link_index;
    uint16_t link_count;
    uint32_t file_attribs;
    uint64_t usn;
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_modification_time;
    uint64_t access_time;
} FileEntry;

typedef struct {
    uint32_t recno;
    uint32_t base_recno;
    uint64_t frn;
    uint64_t parent_frn;
    char *name;
    uint16_t name_len;
} ExtEntry;

extern LinkEntry *links;
extern uint32_t link_count;
extern uint32_t link_capacity;
extern FileEntry *entries;
extern uint32_t entry_count;
extern uint32_t max_count;
extern uint32_t entry_capacity;
extern ExtEntry *ext;
extern uint32_t ext_count;
extern uint32_t ext_capacity;

uint32_t GetFileRecordSize(const BootSector *bs);
int apply_usa(unsigned char *buf, uint16_t bytesPerSector);
void Read(HANDLE drive, void *buffer, uint64_t from, DWORD count);
void EnsureEntryCapacity(uint32_t recno);
int BuildDirPath(uint32_t recno, char *out, size_t outSize);
int BuildPath(uint32_t recno, const char *name, uint16_t name_len, char *out, size_t outSize);
uint64_t ntfs_to_epoch_us(uint64_t ntfs);
uint64_t ParseDatetimeToNtfs(const char *input);
uint64_t ParseAttributes(HANDLE h, unsigned char *buf, uint32_t record_size, FILE_RECORD_HEADER *hrec, uint64_t bytesPerCluster, uint16_t bytesPerSector, bool deleted, bool has_target);
void free_processed(unsigned char *buff);
