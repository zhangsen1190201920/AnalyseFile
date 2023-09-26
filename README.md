# AnalyseFile
这个程序可以用于读取正则文件并使用hyperscan引擎提取包括txt,doc，ppt等类型文件的敏感信息。
编译指令

gcc ./libdoc.so ./libxls.so main.c -lhs -lstdc++ -lm -l mysqlclient -ldl -o main
运行方式
./main
