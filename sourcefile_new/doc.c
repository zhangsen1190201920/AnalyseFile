#include "doc.h"
#include "common_struct.h"
void fail(char* msg){
    fprintf(stderr, "%s\n", msg);
}

int find_sector(struct doc_file* doc, int idx){
    return fseek(doc->file, DOC_HEADER_LEN + doc->sector_size*idx, SEEK_SET);
}

int next_secid(struct secids *secids, int idx){
    struct secids* target = secids;
    while(idx >= 128){
        target = secids->next;
        idx -= 128;
    }
    return target->ids[idx];
}

int read_sat(struct doc_file* doc){
    int cnt = 1;
    // read first sat
    doc->sat_secids = (struct secids*) malloc(sizeof(struct secids));
    if(find_sector(doc, doc->header->msat[0])) 
        goto bad;
    if(fread(doc->sat_secids->ids, 4, 128, doc->file) != 128)
        goto bad;
    doc->sat_secids->next = 0;
    struct secids* curr = doc->sat_secids;
    // read MSAT in header
    for(int i = 1; i < 109 && doc->header->msat[i] > 0; i++){
        curr->next = (struct secids*) malloc(sizeof(struct secids));
        curr = curr->next;
        curr->next = 0;
        if(find_sector(doc, doc->header->msat[i])) 
            goto bad;
        if(fread(curr->ids, 4, 128, doc->file) != 128)
            goto bad;
        cnt++;
    }
    // read MSAT in other sectors if exists.
    int secid = doc->header->msat_secid;
    int msat[128];
    while(secid != END_OF_CHAIN){
        if(find_sector(doc, secid)) 
            goto bad;
        if(fread(msat, 4, 128, doc->file) != 128)
            goto bad;
        for(int i = 0; i < 127 && msat[i] > 0; i++){
            curr->next = (struct secids*) malloc(sizeof(struct secids));
            curr = curr->next;
            curr->next = 0;
            if(find_sector(doc, msat[i])) 
                goto bad;
            if(fread(curr->ids, 4, 128, doc->file) != 128)
                goto bad;
        cnt++;
        }
        secid = msat[127];
    }
    if(cnt != doc->header->sat_secnum)
        goto bad;
    return 0;
bad:
    return -1;
}

int read_ssat(struct doc_file* doc){
    int secid = doc->header->ssat_secid;
    struct secids **curr = &doc->ssat_secids;
    while(secid != END_OF_CHAIN){
        *curr = (struct secids*) malloc(sizeof(struct secids));
        if(find_sector(doc, secid))
            goto bad;
        if(fread((*curr)->ids, 4, 128, doc->file) != 128)
            goto bad;
        (*curr)->next = 0;
        curr = &((*curr)->next);
        secid = next_secid(doc->sat_secids, secid);
    }
    return 0;
bad:
    return -1;
}

void free_sat(struct secids* secids){
    if(secids->next){
        free_sat(secids->next);
    }
    free(secids);
}

int read_dirtree(struct doc_file *doc){
    int secid = doc->header->dir_stream_secid;
    int cnt = 0;
    while(secid != END_OF_CHAIN){
        secid = next_secid(doc->sat_secids, secid);
        cnt++;
    }
    doc->directories = (struct directory*) malloc(cnt * doc->sector_size);
    secid = doc->header->dir_stream_secid;
    struct directory* dir = doc->directories;
    int rootid = 1;
    cnt = 0;
    while(secid != END_OF_CHAIN){
        if(find_sector(doc, secid))
            goto bad;
        if(fread(dir, 128, 4, doc->file) != 4)
            goto bad;
        for(int id = cnt*4; id < cnt*4+4; id++){ 
            if(!memcmp("\0\0", doc->directories[id].name, 2)){
                break;
            }
            if(!memcmp("W\0o\0r\0d\0D\0o\0c\0u\0m\0e\0n\0t\0", doc->directories[id].name, 24)){
                doc->word_document_stream = &(doc->directories[id]);
            }
            if(doc->directories[id].lchild == rootid || doc->directories[id].rchild == rootid){
                rootid = id;
            }
            doc->dirnum++;
        }
        cnt++;
        dir += 4;
        secid = next_secid(doc->sat_secids, secid);
    }
    doc->root_stream = &(doc->directories[rootid]);
    if((!doc->word_document_stream) || (!doc->dirnum))
        goto bad;
    return 0;
bad:
    return -1;
}

unsigned long utf16_to_unicode(char* text){
    unsigned int unicode;
    unsigned long sz;
    unsigned short high = *(unsigned short*)text;
    if(high >> 10 == 0x36){
        unsigned short low = *((unsigned short*)&text + 1);
        unicode = ((high & 0x3ff) << 10) + (low & 0x3ff);
        sz = 4;
    }
    else{
        unicode = high;
        sz = 2;
    }
    return (sz << 32) + unicode;
}

int unicode2utf8(int unicode, char* dst){
    if(unicode < 0x80){
        *dst = (unsigned char)unicode;
        return 1;
    }
    else if(unicode < 0x800){
        *dst = (unsigned char)((unicode>>6)&0x1f|0xc0);
        dst++;
        *dst = (unsigned char)(unicode&0x3f|0x80);
        return 2;
    }
    else if(unicode < 0x10000){
        *dst = (unsigned char)((unicode>>12)&0x0f|0xe0);
        dst++;
        *dst = (unsigned char)((unicode>>6)&0x3f|0x80);
        dst++;
        *dst = (unsigned char)(unicode&0x3f|0x80);
        return 3;
    }
    else{
        *dst = (unsigned char)((unicode>>18)&0x07|0xf0);
        dst++;
        *dst = (unsigned char)((unicode>>12)&0x3f|0x80);
        dst++;
        *dst = (unsigned char)((unicode>>6)&0x3f|0x80);
        dst++;
        *dst = (unsigned char)(unicode&0x3f|0x80);
        return 4;
    }
    return 0;
}

int guess_encode(char* text, int size){
    // todo: add utf16 support
    int is_word_ascii = 1;
    int is_utf16 = 1;
    // check ascii
    for(int i = 0; i < size; i++){
        if(text[i] > 0 || ((unsigned char)text[i] >= 0x91 && (unsigned char)text[i] <= 0x94)){
            // [1, 0x7f] & [0x91, 0x94]
            continue;
        }
        else{
            is_word_ascii = 0;
            break;
        }
    }
    if(is_word_ascii){
        return WORD_ASCII;
    }
    // check utf16
    int chs[29] = { // 标点符号
        8211, 8212, 8216, 8217, 8220, 8221, 
        8230, 12289, 12290, 12296, 12297, 12298, 
        12299, 12300, 12301, 12302, 12303, 12304, 
        12305, 12308, 12309, 65281, 65288, 65289, 
        65292, 65294, 65306, 65307, 65311
    };
    int n = 0;
    while(n < size){
        unsigned long res = utf16_to_unicode(&(text[n]));
        int sz = res >> 32;
        unsigned int unicode = res & 0xffffffff;
        if(sz != 2){
            is_utf16 = 0;
            break;
        }
        n += 2;
        // [0, 0x7f]
        if(unicode < 0x80){
            continue;
        }
        // 汉字
        if(unicode >= 0x4E00 && unicode <= 0x9fff){
            continue;
        }
        // 全角标点
        int is_ch = 0;
        for(int i = 0; i < 29; i++){
            if(chs[i] == unicode){
                is_ch = 1;
                break;
            }
        }
        if(!is_ch){
            is_utf16 = 0;
            break;
        }
    }
    return is_utf16? CN_UTF16: NOTTEXT;
}

// receive utf8/utf16 encoding string from src, copy utf8 string to dst
size_t strencodencpy(char* src, char* dst, size_t max, int encode){
    size_t size = 0;
    size_t idx = 0;
    switch (encode){
    case WORD_ASCII:
        for(size_t i = 0; i < max; i++){
            if(src[i] >= 0){
                dst[i] = src[i];
                if(src[i] == 0){
                    break;
                }
            }
            else if(src[i] == (char)0x91 || src[i] == (char)0x92){
                dst[i] = '\'';
            }
            else if(src[i] == (char)0x93 || src[i] == (char)0x94){
                dst[i] = '\"';
            }
            if(src[i] == '\r'){
                dst[i] = '\n';
            }
            size++;
        }
        break;
    case CN_UTF16:
        while(idx < max){
            unsigned long res = utf16_to_unicode(&(src[idx]));
            int sz = res >> 32;
            idx += sz;
            unsigned int unicode = res & 0xffffffff;
            sz = unicode2utf8(unicode, &(dst[size]));
            if(sz == 1){
                if(dst[size] == 0){
                    break;
                }
                if(dst[size] == '\r'){
                    dst[size] = '\n';
                }
            }
            size += sz;
        }
        break;
    default:
        break;
    }
    return size;
}

ssize_t get_utf8_text(struct doc_file* doc, char** textaddr){
    size_t size = 0;
    int secid = doc->word_document_stream->secid;
    int block_sz = 2048;
    int block_num = 1;
    *textaddr = (char*) malloc(block_sz*block_num);
    char sector[512];
    struct secids * ids = doc->word_document_stream->size < doc->header->std_stream_minsize ? doc->ssat_secids: doc->sat_secids;
    while(secid != END_OF_CHAIN){
        if(find_sector(doc, secid))
            goto bad;
        if(fread(sector, 1, doc->sector_size, doc->file) != doc->sector_size)
            goto bad;
        int encode = guess_encode(sector, 8);
        size += strencodencpy(sector, (*textaddr) + size, doc->sector_size, encode);
        if(block_sz*block_num - size < 1024){
            block_num++;
            *textaddr = (char*) realloc(*textaddr, block_sz*block_num);
        } 
        secid = next_secid(ids, secid);
    }
    return size;
bad:
    if(*textaddr){
        free(*textaddr);
        *textaddr = 0;
    }
    return -1;
}

struct doc_file* doc_init(char* filename){
    struct doc_file* doc = (struct doc_file*) malloc(sizeof(struct doc_file));
    memset(doc, 0, sizeof(struct doc_file));
    doc->filename = filename;
    doc->file = fopen(filename, "rb");
    fseek(doc->file, 0, SEEK_END);
    doc->size = ftell(doc->file);
    fseek(doc->file, 0, SEEK_SET);
    doc->header = (struct doc_header*) malloc(sizeof(struct doc_header));
    if(fread(doc->header, 1, 512, doc->file) < DOC_HEADER_LEN){ // header length: 512
        fail("fail to read doc header");
        goto bad;
    }
    if(memcmp(doc->header->magic, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8)){
        fail("wrong magic number");
        goto bad;
    }
    if(doc->header->byte_order != 0xfffe){
        fail("not little endian");
        goto bad;
    }
    if(doc->header->ssz != 9 || doc->header->sssz != 6){
        fail("unsupported sector size");
        goto bad;
    }
    doc->sector_size = 1 << doc->header->ssz;
    if(read_sat(doc)){
        fail("read SAT fail");
        goto bad;
    }
    if(read_ssat(doc)){
        fail("read SSAT fail");
        goto bad;
    }
    if(read_dirtree(doc)){
        fail("read directory tree fail");
        goto bad;
    }
    return doc;
bad:
    doc_clear(doc);
    return 0;
}

void doc_clear(struct doc_file* doc){
    fclose(doc->file);
    if(doc->directories){
        free(doc->directories);
    }
    if(doc->header){
        free(doc->header);
    }
    if(doc->sat_secids){
        free_sat(doc->sat_secids);
    }
    if(doc->ssat_secids){
        free_sat(doc->ssat_secids);
    }
}