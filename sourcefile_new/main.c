#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <hs.h>
#include <mysql/mysql.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>
#include "doc.h"
#include "xls.h"
#define MYSQL_HOST "152.136.198.41"
#define MYSQL_USER "root"
#define MYSQL_PASSWD "bj999888"
#define DB_NAME "data_classification"
#define TABLE_NAME "file_scan_result"
#define MY_HTTP_DEFAULT_PORT 80
#define BUFFER_SIZE 1024
#define HTTP_POST "POST /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n" \
                  "Content-Type:application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"
#define HTTP_GET "GET /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n\r\n"

static bool doc_check = false;
static bool ppt_check = false;
static bool pdf_check = false;
static bool txt_check = false;
static bool xls_check = false;
// parse ppt file to get content
static int (*http_ppt_parse)();
// parse pdf file to get content
static int (*http_pdf_parse)();
// parse docx file to get content
static int (*http_docx_parse)();
// parse pptx file to get content
static int (*http_pptx_parse)();
// parse xlsx file to get content
static int (*http_xlsx_parse)();
char failurl[] = "http://114.215.27.239:7001/restful/state/-1";
//根据tasknum.conf中的filetype来确定检查何种文件,比如有0检查doc
//文件类型：0:doc，1:PPT，2:PDF 3:TXT 4:XLS
struct secids
{
    struct secids *next;
    int ids[128];
};

// directory in a .doc file. DO NOT change
struct directory
{
    char name[64];
    short namelen;
    char type;
    char color; // red-black tree node color
    int lchild;
    int rchild;
    int root;
    char identifier[16];
    unsigned int flags;
    unsigned int creation_time[2];
    unsigned int modification_time[2];
    int secid;
    int size;
    int unused;
};
int ids[10000];
char *patterns[10000];
int flag[10000];
int pattern_num;

// hyperscan 参数
struct event_data
{
    char *dataPointer;
    char **patterns;
    char *filepath;
};
int readFileList(char *basePath);
static char *readFileData(const char *inputFN, unsigned int *length);
static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx);
int readREgexPaser(char *path, int ids[], char *patterns[], int flag[]);
int readTaskNum(char *path, char *basePath);
int hyperScanProcess(char *address, char *patterns[], int flags[], int ids[], int pattern_length, char *inputData, unsigned int length);
void mysqldb_connect(MYSQL *mysql);
void mysqldb_insert(MYSQL *mysql, int ruleid, char *filepath, char *content);
static int http_tcpclient_create(const char *host, int port);
static int http_parse_url(const char *url, char *host, char *file, int *port);
static void http_tcpclient_close(int socket);
static int http_tcpclient_recv(int socket, char *lpbuff);
char *http_post(const char *url, const char *post_str);
char *http_get(const char *url);
static char regexConfigPath[100] = "\0"; // get regex conf basepath in main
static char taskNumPath[200] = "\0";     // get tasknum conf basepath in main
static char taskNumName[200] = "\0";     // get tasknum

void *load_sym(const char *lib_name, const char *sym)
{
    void *handle = 0, *psym = 0;
    char *error = 0;

    handle = dlopen(lib_name, RTLD_LAZY);
    if (handle == 0)
    {
        return 0;
    }
    psym = dlsym(handle, sym);
    if ((error = dlerror()) != 0)
    {
        return 0;
    }
    //	dlclose(handle);
    return psym;
}

static void load_one_sym(const char *lib_name, const char *sym, void **psym)
{
    *psym = load_sym(lib_name, sym);
    if (*psym == 0)
    {
        fprintf(stderr, "%s.%d F %s %s\n", __FILE__, __LINE__, lib_name, sym);
        exit(100);
    }
}

static void load_all_syms()
{
    load_one_sym("./libppt.so", "ppt_text_file", (void **)&http_ppt_parse);
    load_one_sym("./liboffice.so", "docx_parser", (void **)&http_docx_parse);
    load_one_sym("./liboffice.so", "pptx_parser", (void **)&http_pptx_parse);
    load_one_sym("./liboffice.so", "xlsx_parser", (void **)&http_xlsx_parse);
     load_one_sym("./libpdf.so","pdf_text_extraction",(void**)&http_pdf_parse);
}

// address 为读取文件的地址，patterns为全局变量正则表，flags为对应正则的规则，ids为对应pattern的标号，pattern_length为正则规则的总个数，inputData为输入数据，length为其长度。
int hyperScanProcess(char *address, char *patterns[], int flags[], int ids[], int pattern_length, char *inputData, unsigned int length)
{
    hs_stream_t *steams[1];
    char *inputFN = address;
    struct event_data data;
    struct event_data *ptr = &data;
    ptr->patterns = patterns;
    /* First, we attempt to compile the pattern provided on the command line.
     * We assume 'DOTALL' semantics, meaning that the '.' meta-character will
     * match newline characters. The compiler will analyse the given pattern and
     * either return a compiled Hyperscan database, or an error message
     * explaining why the pattern didn't compile.
     */
    hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile_multi(patterns, flags, ids, pattern_length, HS_MODE_BLOCK, NULL, &database, &compile_err))
    {
        fprintf(stderr, "ERROR: Unable to compile pattern : %s\n", compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }

    /* Next, we read the input data file into a buffer. */
    if (!inputData)
    {
        hs_free_database(database);
        return -1;
    }
    ptr->filepath = inputFN;
    ptr->dataPointer = inputData;

    /* Finally, we issue a call to hs_scan, which will search the input buffer
     * for the pattern represented in the bytecode. Note that in order to do
     * this, scratch space needs to be allocated with the hs_alloc_scratch
     * function. In typical usage, you would reuse this scratch space for many
     * calls to hs_scan, but as we're only doing one, we'll be allocating it
     * and deallocating it as soon as our matching is done.
     *
     * When matches occur, the specified callback function (eventHandler in
     * this file) will be called. Note that although it is reminiscent of
     * asynchronous APIs, Hyperscan operates synchronously: all matches will be
     * found, and all callbacks issued, *before* hs_scan returns.
     *
     * In this example, we provide the input pattern as the context pointer so
     * that the callback is able to print out the pattern that matched on each
     * match event.
     */
    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        free(inputData);
        hs_free_database(database);
        return -1;
    }

    printf("Scanning %u bytes with Hyperscan\n", length);

    if (hs_scan(database, inputData, length, 0, scratch, eventHandler,
                ptr) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(scratch);
        free(inputData);
        hs_free_database(database);
        return -1;
    }

    /* Scanning is complete, any matches have been handled, so now we just
     * clean up and exit.
     */
    hs_free_scratch(scratch);
    free(inputData);
    hs_free_database(database);
    return 0;
}

/**
 * This is the function that will be called for each match that occurs. @a ctx
 * is to allow you to have some application-specific state that you will get
 * access to for each match. In our simple example we're just going to use it
 * to pass in the pattern that was being searched for so we can print it out.
 */
static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx)
{
    struct event_data *ptr = (struct event_data *)ctx;
    char *inputdata = ptr->dataPointer;
    printf("%llu %llu\n", from, to);
    char *tmp = (char *)malloc(to - from + 2);
    memset(tmp, '\0', to - from + 2);
    strncpy(tmp, inputdata + from, (int)(to - from));
    printf("Match for pattern %d \"%s\" at offset %llu\n", id, tmp, from);
    MYSQL *mysql = mysql_init(NULL);
    if (!mysql)
    {
        printf("\nMysql init failed.\n");
    }

    //连接MYSQL
    mysqldb_connect(mysql);

    // // 插入数据
    mysqldb_insert(mysql, id, ptr->filepath, tmp);
    mysql_close(mysql);
    free(tmp);
    return 0;
}
/**
 * Fill a data buffer from the given filename, returning it and filling @a
 * length with its length. Returns NULL on failure.
 *
 */
static char *readFileData(const char *inputFN, unsigned int *length)
{
    FILE *f = fopen(inputFN, "rb");
    if (!f)
    {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s\n", inputFN,
                strerror(errno));
        return NULL;
    }

    /* We use fseek/ftell to get our data length, in order to keep this example
     * code as portable as possible. */
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }
    long dataLen = ftell(f);
    if (dataLen < 0)
    {
        fprintf(stderr, "ERROR: ftell() failed: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }

    /* Hyperscan's hs_scan function accepts length as an unsigned int, so we
     * limit the size of our buffer appropriately. */
    if ((unsigned long)dataLen > UINT_MAX)
    {
        dataLen = UINT_MAX;
        printf("WARNING: clipping data to %ld bytes\n", dataLen);
    }
    else if (dataLen == 0)
    {
        fprintf(stderr, "ERROR: input file \"%s\" is empty\n", inputFN);
        fclose(f);
        return NULL;
    }

    char *inputData = (char *)malloc(dataLen);
    if (!inputData)
    {
        fprintf(stderr, "ERROR: unable to malloc %ld bytes\n", dataLen);
        fclose(f);
        return NULL;
    }

    char *p = inputData;
    size_t bytesLeft = dataLen;
    while (bytesLeft)
    {
        size_t bytesRead = fread(p, 1, bytesLeft, f);
        bytesLeft -= bytesRead;
        p += bytesRead;
        if (ferror(f) != 0)
        {
            fprintf(stderr, "ERROR: fread() failed\n");
            free(inputData);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);

    *length = (unsigned int)dataLen;
    return inputData;
}
// name为传递的字符串，suffix为获得的后缀扩展名
// 成功找到返回1失败返回-1；
//
//
//
//
int getsuffix(char *name, char *suffix)
{
    char *dot = strrchr(name, '.');
    if (!dot)
    {
        return -1;
    }
    else
    {
        strcpy(suffix, dot + 1);
        return 1;
    }
}
// deal with txt
void dealWithTxt(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithTxt%s\n", address);
    unsigned int length;
    char *inputData = readFileData(address, &length);
    if (hyperScanProcess(address, patterns, flag, ids, pattern_num, inputData, length) < 0)
    {
        http_get(failurl);
    }

    // hyperScanProcess(argc, inputDetail);
}
// deal with doc
void dealWithDoc(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithDoc%s\n", address);
    struct doc_file *doc = doc_init(address);
    if (!doc)
    {
        http_get(failurl);
    }
    char *text = 0;
    // 获得文本
    ssize_t size = get_utf8_text(doc, &text);
    if (size > 0)
    {
        // printf("1!!!\n");
        // write(1, text, size);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, text, (unsigned int)size) < 0)
        {
            http_get(failurl);
        }
    }
    else
    {
        printf("fail to extract text! ret: %ld\n", size);
        http_get(failurl);
    }
    // 清理内存
    doc_clear(doc);
    // 注意：text内存的释放是hyperscanprocess的义务。这一点的设计出于组里的项目需求考虑
}
void dealWithDocx(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithDocx%s\n", address);
    char *file_content = NULL;
    ssize_t content_len = 0;
    content_len = http_docx_parse(address, NULL, &file_content, 2);
    if (content_len > 0)
    {
         //write(1, file_content, content_len);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, file_content, (unsigned int)content_len) < 0)
        {
            http_get(failurl);
        }
    }
}
void dealWithXlsx(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithXlsx%s\n", address);
    char *file_content = NULL;
    ssize_t content_len = 0;
    content_len = http_xlsx_parse(address, NULL, &file_content, 2);
    if (content_len > 0)
    {
         //write(1, file_content, content_len);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, file_content, (unsigned int)content_len) < 0)
        {
            http_get(failurl);
        }
    }
}
void dealWithPptx(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithPptx%s\n", address);
    char *file_content = NULL;
    ssize_t content_len = 0;
    content_len = http_pptx_parse(address, NULL, &file_content, 2);
    if (content_len > 0)
    {
         //write(1, file_content, content_len);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, file_content, (unsigned int)content_len) < 0)
        {
            http_get(failurl);
        }
    }
}
void dealWithPdf(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 1);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("dealwithPptx%s\n", address);
    char *file_content = NULL;
    ssize_t content_len = 0;
    content_len = http_pdf_parse(address, NULL, &file_content, 2);
    if (content_len > 0)
    {
         //write(1, file_content, content_len);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, file_content, (unsigned int)content_len) < 0)
        {
            http_get(failurl);
        }
    }
}
// deal with xls
void dealWithXls(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 2);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("%s\n", address);
    struct xls_file *xls = xls_init(address);
    if (!xls)
    {
        http_get(failurl);
    }
    char *text = 0;
    size_t sz = xls_output_text(xls, &text);
    if (sz > 0)
    {
        // write(1, text, sz);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, text, (unsigned int)sz) < 0)
        {
            http_get(failurl);
        }
    }

    // clear
    xls_clear(xls);
}
void dealWithPpt(char *basePath, const struct dirent *ptr)
{
    int addressLength = (strlen(basePath) + strlen("/") + strlen(ptr->d_name) + 2);
    char *address = (char *)malloc(addressLength * sizeof(char));
    memset(address, '\0', addressLength);
    strcpy(address, basePath);
    strcat(address, "/");
    strcat(address, ptr->d_name);
    printf("%s\n", address);
    char *file_content = NULL;
    ssize_t content_len = 0;
    content_len = http_ppt_parse(address, &file_content);
    if (content_len > 0)
    {
        // write(1, file_content, content_len);
        if (hyperScanProcess(address, patterns, flag, ids, pattern_num, file_content, (unsigned int)content_len) < 0)
        {
            http_get(failurl);
        }
    }
}
/*
使用C语言查找一个文件夹下指定.conf扩展名的文件
*/
int getConfInDir(char *DirPath, char *FileName)
{
    DIR *dir;
    struct dirent *ptr;

    if ((dir = opendir(DirPath)) == NULL)
    {
        perror("Open dir error...");
        exit(1);
    }

    char *CurFileExtName = NULL;
    while ((ptr = readdir(dir)) != NULL)
    {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) /// current dir OR parrent dir
            continue;                                                        //跳过.和..目录
        else if (ptr->d_type == 8)                                           /// d_type=8对应file
        {
            char *suffix = (char *)malloc(10 * sizeof(char));
            int result = getsuffix(ptr->d_name, suffix);
            if (result > 0)
            {
                // printf("%s\n", ptr->d_name); // show suffix
                if (!strcmp(suffix, "scanConf"))
                {
                    printf("%s\n", ptr->d_name); // show suffix
                    strcpy(FileName, ptr->d_name);
                    strcpy(taskNumPath, DirPath);
                    strcat(taskNumPath, "/");
                    strcat(taskNumPath, ptr->d_name); // get tasknumpath!
                    strncpy(taskNumName, ptr->d_name, strlen(ptr->d_name) - 9);
                    printf("%s\n", taskNumName);
                    closedir(dir);
                    char workpath[1000] = "\0";
                    result = readTaskNum(taskNumPath, workpath); // change basepath and other configs
                                                                 /// get the file list
                    if (result < 0)
                    {
                        printf("ERROR: Unable to get tasknum config. Exiting.\n");
                        return -1;
                    }
                    remove(taskNumPath);
                    readFileList(workpath);
                    char postMessage[500];
                    char baseurl[] = "http://114.215.27.239:7001/restful/state/";
                    char url[500];
                    sprintf(url, "%s%s", baseurl, taskNumName);
                    printf("%s\n", url);
                    sprintf(postMessage, "{\"isScanFinish\": true,\"taskNumber\": \"%s\"}", taskNumName);
                    // printf("%s\n", postMessage);
                    // http_get(url);
                    printf("%s\n", http_get(url));
                    return 1;
                }
            }
        }
    }
    closedir(dir);

    return -1;
}
/*
读取要求解析文件路径
*/
int readFileList(char *basePath)
{
    DIR *dir;
    struct dirent *ptr;
    char base[1000];
    printf("%s\n", basePath);

    if ((dir = opendir(basePath)) == NULL)
    {
        perror("Open dir error...");
        exit(1);
    }

    while ((ptr = readdir(dir)) != NULL)
    {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) /// current dir OR parrent dir
            continue;
        else if (ptr->d_type == 8) /// file
        {
            printf("d_name:%s/%s\n", basePath, ptr->d_name);
            char *suffix = (char *)malloc(10 * sizeof(char));
            int result = getsuffix(ptr->d_name, suffix);
            if (result > 0)
            {
                // printf("%s\n", suffix); //show suffix
                if (!strcmp(suffix, "txt") && txt_check == true)
                {

                    dealWithTxt(basePath, ptr);
                }
                // deal with doc !
                if (!strcmp(suffix, "doc") && doc_check == true)
                {
                    dealWithDoc(basePath, ptr);
                }
                if (!strcmp(suffix, "docx") && doc_check == true)
                {
                    dealWithDocx(basePath, ptr);
                }
                // deal with xls !
                if (!strcmp(suffix, "xls") && xls_check == true)
                {
                    dealWithXls(basePath, ptr);
                }
                // deal with ppt!
                if (!strcmp(suffix, "ppt") && ppt_check == true)
                {
                    dealWithPpt(basePath, ptr);
                }
                 if (!strcmp(suffix, "pptx") && ppt_check == true)
                {
                    dealWithPptx(basePath, ptr);
                }
                 if (!strcmp(suffix, "xlsx") && xls_check == true)
                {
                    dealWithXlsx(basePath, ptr);
                }
                if (!strcmp(suffix, "pdf") && pdf_check == true)
                {
                    dealWithPdf(basePath, ptr);
                }
            }
            else
            {
            }
            free(suffix);
        }

        else if (ptr->d_type == 10) /// link file
            printf("d_name:%s/%s\n", basePath, ptr->d_name);
        else if (ptr->d_type == 4) /// dir
        {
            memset(base, '\0', sizeof(base));
            strcpy(base, basePath);
            strcat(base, "/");
            strcat(base, ptr->d_name);
            readFileList(base);
        }
    }
    closedir(dir);
    return 1;
}

int main(void)
{
    DIR *dir;
    load_all_syms();
    char basePath[1000];

    /// get the current absoulte path
    memset(basePath, '\0', sizeof(basePath));
    getcwd(basePath, 999); //参数说明：getcwd()会将当前工作目录的绝对路径复制到参数buffer所指的内存空间中,参数size为buf的空间大小。
    printf("the current dir is : %s\n", basePath);
    strcpy(regexConfigPath, basePath);
    strcat(regexConfigPath, "/");
    strcat(regexConfigPath, "regex.mtxt");
    printf("%s\n", regexConfigPath);
    pattern_num = readREgexPaser(regexConfigPath, ids, patterns, flag);
    if (pattern_num == 0)
    {
        printf("can't read parser!exit\n");
        exit(1);
    }
    for (int i = 0; i < pattern_num; i++)
    {
        printf("%d:%s  %d\n", ids[i], patterns[i], flag[i]);
    }
    printf("%d\n", pattern_num);
    int result = getConfInDir(basePath, taskNumPath);
    if (result < 0)
    {
        printf("ERROR: Unable to get config path. Exiting.\n");
        return -1;
    }
    return 0;
}
// get tasknum content and change path to dest path
int readTaskNum(char *path, char *basePath)
{
    FILE *fp;
    int pattern_num = 0;
    printf("%s\n", path);
    fp = fopen(path, "rw");
    memset(basePath, '\0', sizeof(basePath));
    char absolutePath[] = "absolutePath:";
    char fileType[] = "fileType:";
    if (NULL == fp)
    {
        printf("open %s failed.\n", path);
        return -1;
    }
    printf("open %s successed.\n", path);
    char mystring[10000];
    int offset = 0;
    if (fgets(mystring, 10000, fp) != NULL)
    {
        char tmp[20] = "\0";
        strncpy(tmp, mystring, 13);
        if (strcmp(tmp, absolutePath) == 0)
        {
            char *row = strchr(mystring, '\n');
            if (row)
            {
                *row = '\0';
            }
            int offset = row - mystring;
            strcpy(basePath, mystring + 13);
            printf("basepath:%s\n", basePath); // change basepath!
            if (fgets(mystring, 10000, fp) != NULL)
            {
                char *nextrow = mystring;
                memset(tmp, '\0', sizeof(tmp));
                strncpy(tmp, nextrow, 9);
                printf("%s\n", tmp);
                if (strcmp(tmp, fileType) == 0)
                {
                    char *Left_bracket = strchr(nextrow, '[');
                    char *Right_bracket = strchr(nextrow, ']');
                    memset(tmp, '\0', sizeof(tmp));
                    strncpy(tmp, Left_bracket + 1, Right_bracket - Left_bracket - 1);
                    // printf("%s\n", tmp);
                    char *p;
                    const char *delim = ",";
                    p = strtok(tmp, delim);
                    while (p != NULL)
                    {
                        printf("%d \n", atoi(p));
                        int key = atoi(p);
                        switch (key)
                        {
                        case 0:
                            doc_check = true;
                            break;
                        case 1:
                            ppt_check = true;
                            break;
                        case 2:
                            pdf_check = true;
                            break;
                        case 3:
                            txt_check = true;
                            break;
                        case 4:
                            xls_check = true;
                            break;
                        default:
                            printf("number exist,but don't effect!\n");
                            break;
                        }
                        p = strtok(NULL, delim);
                    }
                }
                else
                {
                    printf("Wrong format! in filetype in file %s\n", path);
                    return -1;
                }
            }
        }
        else
        {
            printf("Wrong format! in absolutePath in file %s\n", path);
            return -1;
        }
    }
    fclose(fp);
    return 1;
}
int readREgexPaser(char *path, int ids[], char *patterns[], int flags[])
{
    FILE *fp;
    fp = fopen(path, "rw");
    if (NULL == fp)
    {
        printf("open %s failed.\n", path);
        return -1;
    }
    printf("%s\n", path);

    char mystring[10000];
    memset(mystring, '\0', sizeof(mystring));
    int i = 0;
    int ch = 0;
    while (fgets(mystring, 10000, fp) != NULL)
    {
        if (strlen(mystring) > 9000)
        {
            do
            {
                /* read a char from the file */
                ch = fgetc(fp);
                /* display the character */
                // putch(ch);
            } while (ch != '\n');
            continue;
        }
        char *filter1 = strstr(mystring, "\\u");
        if (filter1)
        {
            continue;
        }
        char *filter2;
        filter2 = strchr(mystring, '?');
        if (filter2)
        {
            continue;
        }
        // printf("%s\n",path);
        char *find = strchr(mystring, '\n');
        if (find)
            *find = '\0';
        find = strchr(mystring, 13);
        if (find)
            *find = '\0';
        //  printf("%s\n", mystring);
        //  printf("length %ld\n", strlen(mystring));
        patterns[i] = (char *)malloc(strlen(mystring) + 1);
        char *p = strchr(mystring, ':');
        char *num = (char *)malloc(5);
        memset(num, '\0', 5);
        // printf("%p\n", mystring);
        // printf("%s\n", p);
        strncpy(num, mystring, p - mystring);
        //  printf("%s\n", num);
        ids[i] = atoi(num);
        //  printf("id: %d\n", ids[i]);
        strcpy(patterns[i], p + 1);
        // printf("patterns :  %s\n", patterns[i]);

        // printf("utf-8\n");
        // printf("patterns :  %s\n", patterns[i]);
        flags[i] = HS_FLAG_DOTALL | HS_FLAG_SOM_LEFTMOST | HS_FLAG_UTF8;
        // printf("\n");
        // printf("\n");
        i++;
        pattern_num++;
        memset(mystring, '\0', sizeof(mystring));
    }
    fclose(fp);

    return pattern_num;
}
void mysqldb_connect(MYSQL *mysql)
{
    if (!mysql_real_connect(mysql, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWD, DB_NAME, 0, NULL, 0))
    {
        printf("\nFailed to connect:%s\n", mysql_error(mysql));
    }
    else
    {
        printf("\nConnect sucessfully!\n");
    }
}

/* 插入数据 */
void mysqldb_insert(MYSQL *mysql, int ruleid, char *filepath, char *content)
{
    int t;
    char *head = (char *)"INSERT INTO ";
    char query[2000];
    char field[] = "taskNumber,ruleId,filePath,create_time,sampling_results";
    char *left = (char *)"(";
    char *right = (char *)") ";
    char *values = (char *)"VALUES";
    char message[1000] = {'\0'};
    static char s[30] = {0};
    char YMD[15] = {0};
    char HMS[10] = {0};
    time_t current_time;
    struct tm *now_time;

    char *cur_time = (char *)malloc(30 * sizeof(char));
    memset(cur_time, '\0', 34);
    time(&current_time);
    now_time = localtime(&current_time);

    strftime(YMD, sizeof(YMD), "%F ", now_time);
    strftime(HMS, sizeof(HMS), "%T", now_time);

    strncat(cur_time, YMD, 11);
    strncat(cur_time, HMS, 8);

    printf("%s\n", cur_time);

    sprintf(message, "\"%s\" ,%d, \"%s\" ,\"%s\" ,\"%s\"", taskNumName, ruleid, filepath, cur_time, content);

    /* 拼接sql命令 */
    sprintf(query, "%s%s%s%s%s%s%s%s%s", head, TABLE_NAME, left, field, right, values, left, message, right);
    printf("%s\n", query);

    t = mysql_real_query(mysql, query, strlen(query));
    if (t)
    {
        printf("Failed to query: %s\n", mysql_error(mysql));
    }
    else
    {
        printf("\nInsert sucessfully!\n");
    }
    free(cur_time);

    cur_time = NULL;
}

static int http_tcpclient_create(const char *host, int port)
{
    struct hostent *he;
    struct sockaddr_in server_addr;
    int socket_fd;

    if ((he = gethostbyname(host)) == NULL)
    {
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return -1;
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        return -1;
    }

    return socket_fd;
}

static void http_tcpclient_close(int socket)
{
    close(socket);
}

static int http_parse_url(const char *url, char *host, char *file, int *port)
{
    char *ptr1, *ptr2;
    int len = 0;
    if (!url || !host || !file || !port)
    {
        return -1;
    }

    ptr1 = (char *)url;

    if (!strncmp(ptr1, "http://", strlen("http://")))
    {
        ptr1 += strlen("http://");
    }
    else
    {
        return -1;
    }

    ptr2 = strchr(ptr1, '/');
    if (ptr2)
    {
        len = strlen(ptr1) - strlen(ptr2);
        memcpy(host, ptr1, len);
        host[len] = '\0';
        if (*(ptr2 + 1))
        {
            memcpy(file, ptr2 + 1, strlen(ptr2) - 1);
            file[strlen(ptr2) - 1] = '\0';
        }
    }
    else
    {
        memcpy(host, ptr1, strlen(ptr1));
        host[strlen(ptr1)] = '\0';
    }
    // get host and ip
    ptr1 = strchr(host, ':');
    if (ptr1)
    {
        *ptr1++ = '\0';
        *port = atoi(ptr1);
    }
    else
    {
        *port = MY_HTTP_DEFAULT_PORT;
    }

    return 0;
}

static int http_tcpclient_recv(int socket, char *lpbuff)
{
    int recvnum = 0;

    recvnum = recv(socket, lpbuff, BUFFER_SIZE * 4, 0);

    return recvnum;
}

static int http_tcpclient_send(int socket, char *buff, int size)
{
    int sent = 0, tmpres = 0;

    while (sent < size)
    {
        tmpres = send(socket, buff + sent, size - sent, 0);
        if (tmpres == -1)
        {
            return -1;
        }
        sent += tmpres;
    }
    return sent;
}

static char *http_parse_result(const char *lpbuf)
{
    char *ptmp = NULL;
    char *response = NULL;
    ptmp = (char *)strstr(lpbuf, "HTTP/1.1");
    if (!ptmp)
    {
        printf("http/1.1 not faind\n");
        return NULL;
    }
    if (atoi(ptmp + 9) != 200)
    {
        printf("result:\n%s\n", lpbuf);
        return NULL;
    }

    ptmp = (char *)strstr(lpbuf, "\r\n\r\n");
    if (!ptmp)
    {
        printf("ptmp is NULL\n");
        return NULL;
    }
    response = (char *)malloc(strlen(ptmp) + 1);
    if (!response)
    {
        printf("malloc failed \n");
        return NULL;
    }
    strcpy(response, ptmp + 4);
    return response;
}

char *http_post(const char *url, const char *post_str)
{

    char post[BUFFER_SIZE] = {'\0'};
    int socket_fd = -1;
    char lpbuf[BUFFER_SIZE * 4] = {'\0'};
    char *ptmp;
    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    int port = 0;
    int len = 0;
    char *response = NULL;

    if (!url)
    {
        printf("      failed!\n");
        return NULL;
    }

    if (http_parse_url(url, host_addr, file, &port))
    {
        printf("http_parse_url failed!\n");
        return NULL;
    }
    printf("host_addr : %s\tfile:%s\t,%d\n", host_addr, file, port);

    socket_fd = http_tcpclient_create(host_addr, port);
    if (socket_fd < 0)
    {
        printf("http_tcpclient_create failed\n");
        return NULL;
    }

    sprintf(lpbuf, HTTP_POST, file, host_addr, port, (int)strlen(post_str), post_str);

    if (http_tcpclient_send(socket_fd, lpbuf, strlen(lpbuf)) < 0)
    {
        printf("http_tcpclient_send failed..\n");
        return NULL;
    }
    printf("发送请求:\n%s\n", lpbuf);

    /*it's time to recv from server*/
    if (http_tcpclient_recv(socket_fd, lpbuf) <= 0)
    {
        printf("http_tcpclient_recv failed\n");
        return NULL;
    }

    http_tcpclient_close(socket_fd);

    return http_parse_result(lpbuf);
}

char *http_get(const char *url)
{

    char post[BUFFER_SIZE] = {'\0'};
    int socket_fd = -1;
    char lpbuf[BUFFER_SIZE * 4] = {'\0'};
    char *ptmp;
    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    int port = 0;
    int len = 0;

    if (!url)
    {
        printf("      failed!\n");
        return NULL;
    }

    if (http_parse_url(url, host_addr, file, &port))
    {
        printf("http_parse_url failed!\n");
        return NULL;
    }
    // printf("host_addr : %s\tfile:%s\t,%d\n",host_addr,file,port);

    socket_fd = http_tcpclient_create(host_addr, port);
    if (socket_fd < 0)
    {
        printf("http_tcpclient_create failed\n");
        return NULL;
    }

    sprintf(lpbuf, HTTP_GET, file, host_addr, port);

    if (http_tcpclient_send(socket_fd, lpbuf, strlen(lpbuf)) < 0)
    {
        printf("http_tcpclient_send failed..\n");
        return NULL;
    }
    //	printf("发送请求:\n%s\n",lpbuf);

    if (http_tcpclient_recv(socket_fd, lpbuf) <= 0)
    {
        printf("http_tcpclient_recv failed\n");
        return NULL;
    }
    http_tcpclient_close(socket_fd);

    return http_parse_result(lpbuf);
}
