#ifndef XLS
#define XLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOC_HEADER_LEN 512
#define END_OF_CHAIN -2

#define CELL_TYPE_BLANK   0
#define CELL_TYPE_DOUBLE  1
#define CELL_TYPE_INTEGER 2
#define CELL_TYPE_STRING  3

// records
#define RECORD_EOF      10
#define BoundSheet8     133
#define SST             252
#define LabelSst        253
#define Dimensions      512
#define Row             520
#define RK              638
#define BOF             2057

// Header of a .xls file. DO NOT change
struct xls_header
{
    char magic[8]; // 0-8
    char uid[16]; // 8-24
    unsigned short revision; // 24-26
    unsigned short vision; // 26-28
    unsigned short byte_order; // 28-30
    unsigned short ssz; // 30-32 sec_size = 2^ssz
    unsigned short sssz; // 32-34 short_sec_size = 2^sssz
    char unused0[10]; // 34-44
    int sat_secnum; // 44-48
    int dir_stream_secid; // 48-52
    char unused1[4]; // 52-56
    int std_stream_minsize; //56-60 
    int ssat_secid; // 60-64
    int ssat_secnum; // 64-68
    int msat_secid; // 68-72
    int msat_secnum; // 72-76
    int msat[109]; // 76-512
};


struct stream
{
    struct directory *dir;
    int idx;
    int sec_id;
};

union cellvalue{
    double dnum;
    int inum;
    char* str;
};

struct cell
{
    int type;
    union cellvalue value;
};

struct row
{
    short colMic;
    short colMac;
    struct cell* cells;
    int idx;
};

// worksheet
struct sheet
{
    char* name;
    int rwMic;
    int rwMac;
    short colMic;
    short colMac;
    struct row* rows;
    struct sheet* next;
};

struct shared_strings
{
    char* strings[128];
    struct shared_strings* next;
};

struct xls_file
{
    char* filename;
    FILE* file;
    size_t size;
    unsigned int sector_size;
    struct xls_header* header;
    struct secids *sat_secids;
    struct secids *ssat_secids;
    int dirnum;
    struct directory* directories;
    struct directory* root_stream; // root of directory tree
    struct stream* workbook_stream; // workbook_stream. all sheets here.
    struct shared_strings* sst; // shared strings table
    struct sheet* sheets;
};

struct xls_file*    xls_init(char* filename);
void                xls_clear(struct xls_file* xls);
// output text into a filestream
void                fprint_xls(FILE* file, struct xls_file* xls);
// output text into memory
size_t              xls_output_text(struct xls_file* xls, char** text_addr);

#endif