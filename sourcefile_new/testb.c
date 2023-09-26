#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void test( char * s[])
{

   
    s[1]="15.31";
    
}
int main()
{
    char *s[]={"awdawd","dawdawdwa","zczczcz"};
     printf("%ld\n",sizeof(s));
    test(&s);
    printf("%s\n",s[1]);
    return 0;


}