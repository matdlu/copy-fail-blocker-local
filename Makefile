bpf:
	clang -g -O2 -target bpf -c blocker.c -o blocker.o

loader:
	bpftool gen skeleton blocker.o > blocker.skel.h
	gcc -Wall loader.c -o loader -lbpf -lelf -lz

all: bpf loader

install:
       cp blocker.o /usr/local/lib/bpf/copy_fail_blocker.o
       cp copyfail-filter.service /etc/systemd/system/copyfail-filter.service
       systemctl daemon-reload
       systemctl enable --now copyfail-filter.service

clean:
	rm -f blocker.o
	rm -f blocker.skel.h
	rm -f loader

