#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <hs.h>
#include "cJSON.h"
#include "hyper.h"
#include <dlfcn.h>
/*正则匹配的函数以及回调函数*/
hs_database_t *database;
int regularity_number;
static int (*my_hs_compile_multi)();
static int (*my_hs_scan)();
static int (*my_hs_alloc_scratch)();
static int (*my_hs_free_scratch)();
static int (*my_hs_free_database)();
static int (*my_hs_free_compile_error)();
// static int (*hs_compile_multi)();
// static int (*hs_scan)();
// static int (*hs_alloc_scratch)();
// static int (*hs_free_scratch)();
// static int (*hs_free_database)();
// static int (*hs_alloc_scratch)();
// static int (*hs_free_compile_error)();
void *load_sym (const char *lib_name, const char *sym)
{
    void *handle = 0, *psym = 0;
    char *error = 0;

    handle = dlopen (lib_name, RTLD_LAZY);
    if (handle == 0)
    {
        return 0;
    }
    psym = dlsym (handle, sym);
    if ((error = dlerror()) != 0)
    {
        return 0;
    }
    //	dlclose(handle);
    return psym;
}


/*加载动态链接库*/
static void load_one_sym(const char *lib_name, const char *sym, void **psym)
{
    *psym = load_sym(lib_name, sym);
    if (*psym == 0)
    {
        fprintf(stderr, "%s.%d F %s %s\n", __FILE__, __LINE__, lib_name, sym);
        exit(100);
    }
}

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx)
{
    Node *node = (Node *)ctx;
    cJSON* cjson_head = node->cjson;
    printf("%s\n",cJSON_Print(cjson_head));
    char* inputdata = node->inputdata;
    // printf("Match for pattern \"%d\" at offset from %llu to %llu\n", id, from, to);
    //获得to-from的值
    int offset = to - from;
    // printf("length: %d\n", offset)
    if (offset != 0)
    {
        char which[6];
        memset(which, 0, sizeof(which));
        sprintf(which,"%d",id);
        printf("whichcontent %s\n",cJSON_Print(cJSON_GetObjectItem(cjson_head,which)));
        cJSON* cjson_test = cJSON_GetObjectItem(cjson_head, which);
        char* oldcontent = cJSON_GetObjectItem(cjson_test, "content")->valuestring;
        int contentlength = cJSON_GetObjectItem(cjson_test, "length")->valueint;
        char* newcontent=NULL;
        newcontent = (char*)malloc(contentlength+offset);
        char* hitcontent = (char*)malloc(offset+1);
        memset(hitcontent, 0, offset+1);
        memcpy(hitcontent, inputdata+to-1,offset);
        memset(newcontent, 0, contentlength+offset);
        newcontent = strcat(newcontent, oldcontent);
        if(contentlength!=1){
            newcontent = strcat(newcontent, ";");
        }
        newcontent = strcat(newcontent,hitcontent);
        contentlength = contentlength+offset;
        cJSON_ReplaceItemInObject(cjson_test, "content", cJSON_CreateString(newcontent));
        cJSON_ReplaceItemInObject(cjson_test, "length", cJSON_CreateNumber(contentlength));
        cJSON_ReplaceItemInObject(cjson_head,which,cjson_test);
    }
    return 0;
}
//返回match_result
cJSON *get_match_result(char *inputData)
{
    cJSON *cjson_head = cJSON_CreateObject();
    int i;
    for (i = 0; i < regularity_number; i++)
    {
        char which[6];
        memset(which, 0, sizeof(which));
        sprintf(which,"%d",i);
        cJSON *cjson_test = cJSON_CreateObject();
        /* 添加一条整数类型的JSON数据(添加一个链表节点) */
        cJSON_AddNumberToObject(cjson_test, "model_id", i);
        cJSON_AddStringToObject(cjson_test, "content", "");
        cJSON_AddNumberToObject(cjson_test, "length", 1);
        // 添加cjson_test到cjson_head
        cJSON_AddItemToObject(cjson_head, which, cjson_test);
    }
    Node *node = (Node*)malloc(sizeof(Node));
    node->inputdata = inputData;
    node->cjson = cjson_head;
    // printf("%s\n",inputData);
    //将match_result清零
    unsigned int length;
    length = strlen(inputData);
    hs_scratch_t *scratch = NULL;
    if (my_hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        my_hs_free_database(database);
        return;
    } // length -=1;
    // printf("Scanning %u bytes with Hyperscan\n", length);
    if (my_hs_scan(database, inputData, length, 0, scratch, eventHandler, node) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        my_hs_free_scratch(scratch);
        return;
    } /* Scanning is complete, any matches have been handled, so now we just      * clean up and exit.      */
    my_hs_free_scratch(scratch);
    // printf("%s\n",inputData);
    printf("%s\n",cJSON_Print(cjson_head));
    return cjson_head;
}



//初始化，编译数据库
void hyperscan_init(int ids[], char *patterns[], int length){
    load_one_sym("./libhs.so", "hs_compile_multi", (void **)&my_hs_compile_multi);
    load_one_sym("./libhs.so", "hs_scan", (void **)&my_hs_scan);
    load_one_sym("./libhs.so", "hs_alloc_scratch", (void **)&my_hs_alloc_scratch);
    load_one_sym("./libhs.so", "hs_free_scratch", (void **)&my_hs_free_scratch);
    load_one_sym("./libhs.so", "hs_free_database", (void **)&my_hs_free_database);
    load_one_sym("./libhs.so", "hs_free_compile_error", (void **)&my_hs_free_compile_error);
    regularity_number= length;
    unsigned flags[10000];
    int i = 0;
    for (i = 0; i < length; i++)
    {
        flags[i] = HS_FLAG_SOM_LEFTMOST | HS_FLAG_DOTALL | HS_FLAG_UCP;
    }
    if (database == NULL)
    {
        // int j = 0;
        // for (j = 0; j < pattern_num; j++)
        // for (int i = 0; i < pattern_num; ++i) { fprintf(stdout, "%s\n", patterns[i]);  }
        hs_compile_error_t *compile_err;
        if (my_hs_compile_multi(patterns, flags, ids, length, HS_MODE_BLOCK, NULL, &database, &compile_err) != HS_SUCCESS)
        {
            fprintf(stderr, "error, %s\n", *compile_err);
            my_hs_free_compile_error(compile_err);
            return;
        }
        // my_hs_alloc_scratch(hyper_database, &scratch);
        // while (my_hs_alloc_scratch(hyper_database, &scratch) != HS_SUCCESS) { fprintf(stderr, "not enough!\n");  }
        // fprintf(stdout, "init over!!!\n");
        // exit(0);
    }
}
