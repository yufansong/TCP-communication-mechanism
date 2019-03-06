tar:sender receiver
sender:sender.c ../common/common.c ../common/conf.c
	gcc -o sender sender.c ../common/common.c ../common/conf.c

receiver:receiver.c ../common/common.c ../common/conf.c
	gcc -o receiver receiver.c ../common/common.c ../common/conf.c

clean:
	rm sender receiver *.dat
# # 指令编译器和选项
# CC=g++
# #CFLAGS=-Wall -std=gnu99
 
# # 目标文件
# TARGET=server #receiver
# # 源文件
# SRCS=sender.c ../common/common.c
# # SRCS=sender.c receiver.c ../common/common.c
 
# OBJS = $(SRCS:.c=.o)
 
# $(TARGET):$(OBJS)
# #	@echo TARGET:$@
# #	@echo OBJECTS:$^
# 	$(CC) -o $@ $^
 
# clean:
# 	rm -rf $(TARGET) $(OBJS)
 
# %.o:%.c
# 	# $(CC) -o $@ -c $<
# 	$(CC) $(CFLAGS) -o $@ -c $<

