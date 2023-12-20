# Lecture 2 - ACM Full Stack Networking Winter School.

## Setup 

### Clean iptables and enable ip forwarding

    ```
    # Enable IP-forwarding.
    $ echo 1 > /proc/sys/net/ipv4/ip_forward

    # Flush forward rules.
    $ iptables -P FORWARD ACCEPT
    $ iptables -F FORWARD

    # Flush nat rules.
    $ iptables -t nat -F
    ```

### Compile and install bpftool

Install dependencies (run as root)

    ```
    $ apt-get update -y
    $ apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
        clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl-dev \
        bison flex libbpf-dev iproute2 jq wget apt binutils-dev
    ```

### Setup Golang for userspace

    ```
    export GOVERSION=1.15.8
    mkdir /tmp/golang;
    pushd; cd /tmp/golang;
    wget https://dl.google.com/go/go$\{GOVERSION\}.linux-amd64.tar.gz
    wget https://dl.google.com/go/go${GOVERSION}.linux-amd64.tar.gz
    tar -xzf go${GOVERSION}.linux-amd64.tar.gz
    mv go /usr/local/go${GOVERSION}
    ln -sfn /usr/local/go${GOVERSION} /usr/local/go
    ```

### Get bpftool

    Install from official repository

    ```
    sudo apt-get install linux-tools-generic
    ```

    or compile from source.

    ```
    export KERNEL_GIT=git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
    git clone --depth 1 -b master ${KERNEL_GIT} /tmp/linux && \
    cd /tmp/linux/tools/bpf/bpftool/ &&\
    sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
    sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
    printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
    FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
    strip bpftool && \
    ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
        -e "not a dynamic executable" || \
        ( echo "Error: bpftool is not statically linked"; false )
    ```

### Install iproute2

    ```
    git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
    cd iproute2
    ./configure --prefix=/usr
    sudo make install
    # Copy the `bpf_api.h` helpers file that lives under `./include`
    # to your `/usr/include` directory.
    #
    # ps.: this could be anywhere - including your current source tree.
    install -m 0644 ./include/bpf_api.h /usr/include/iproute2
    ```

### Before running all the tests create a namespace

Sets up a namespaces with two interfaces, veth outside the namespace and
vpeer inside the namespace mimic a contianer setup.

    ```
    ip netns add vns1
    ip link add veth1 type veth peer name vpeer1
    ip link set vpeer1 netns vns1

    ip addr add 192.168.100.1/24 dev veth1
    ip link set veth1 up

    ip netns exec vns1 ip link set lo up
    ip netns exec vns1 ip link set vpeer1 up
    ip netns exec vns1 ip addr add 192.168.100.2/24 dev vpeer1
    ip netns exec vns1 ip route add 192.168.100.1 dev vpeer1
    ip netns exec vns1 ip route add default via 192.168.100.1
    ```

## Hands on with ebpf

In this session you will be using code under the `lecture-2` folder from this repo
[repo](url).

You can clone the repo on your laptops and we can get started.

### Writing an XDP Hello Program

Take a look at the ebpf program stored in `ebpf/ebpf.c`, it is what we can call a
simple ebpf hook point which does not perform any function apart from passing all
the packets through.

Let's go through these steps one by one.

* Take a look at the source code of this program.
* Take a look at the compilation of this program from the `Makefile`.

    You can notice that the program is compile by first asking `clang` to emit ebpf intermediate representation.
    And then converting that to ebpf bytecode using `llc`.

* Lets compile the function by running `make` in the home directory.

    You can notice that a bin directory appears with some bin files.

* You can disassemble the file using `llvm-objdump` and see the contents. Specifically we might be interested in `xdp-pass` section.

    ```
    dushyant @ tcnode6 ➜  lecture-2 git:(master)  llvm-objdump -D --section xdp-pass bin/bpf/ebpf.o

    bin/bpf/ebpf.o:	file format elf64-bpf

    Disassembly of section xdp-pass:

    0000000000000000 <xdp_allow>:
        0:	b7 00 00 00 02 00 00 00	r0 = 2
        1:	95 00 00 00 00 00 00 00	exit
    ```

* Now lets try to load the ebpf program. At load time the verifier will be invoked which will check the ebpf program and if okay load it in the kernel.

    Lets get familiar with `bpftool` to perform this. In simple words `bpftool` is a swiss army knife for bpf which can perform many functions. You must have installed/compiled `bpftool` by now.
    To load the ebpf program we can perform.

    ```
    root@tcnode6:/home/dushyant/tutor/lecture-2# bpftool prog loadall bin/bpf/ebpf.o /sys/fs/bpf/ebpf type xdp -d
    libbpf: loading bin/bpf/ebpf.o
    libbpf: elf: section(3) xdp-pass, size 16, link 0, flags 6, type=1
    libbpf: sec 'xdp-pass': found program 'xdp_allow' at insn offset 0 (0 bytes), code size 2 insns (16 bytes)
    libbpf: elf: section(4) license, size 4, link 0, flags 3, type=1
    libbpf: license of bin/bpf/ebpf.o is GPL
    libbpf: elf: section(13) .BTF, size 515, link 0, flags 0, type=1
    libbpf: elf: section(15) .BTF.ext, size 80, link 0, flags 0, type=1
    libbpf: elf: section(17) .eh_frame, size 48, link 0, flags 2, type=1
    libbpf: elf: skipping unrecognized data section(17) .eh_frame
    libbpf: elf: section(18) .rel.eh_frame, size 16, link 22, flags 40, type=9
    libbpf: elf: skipping relo section(18) .rel.eh_frame for section(17) .eh_frame
    libbpf: elf: section(22) .symtab, size 264, link 1, flags 0, type=2
    libbpf: looking for externs among 11 symbols...
    libbpf: collected 0 externs total
    libbpf: prog 'xdp_allow': unrecognized ELF section name 'xdp-pass'
    libbpf: prog 'xdp_allow': -- BEGIN PROG LOAD LOG --
    func#0 @0
    0: R1=ctx(off=0,imm=0) R10=fp0
    ; return XDP_PASS;
    0: (b7) r0 = 2                        ; R0_w=2
    1: (95) exit
    verification time 23 usec
    stack depth 0
    processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
    -- END PROG LOAD LOG --
    libbpf: prog 'xdp_allow': pinned at '/sys/fs/bpf/ebpf/xdp_allow'
    ```

* Verify if the program loaded correctly using `bpftool prog show` you shoud see something like

    ```
    123800: xdp  name xdp_allow  tag 3b185187f1855c4c  gpl
        loaded_at 2023-12-20T09:31:06+0000  uid 0
        xlated 16B  jited 19B  memlock 4096B
        btf_id 241
    ```

* Now we can attach the ebpf program to a network interface, to do that we can perform.

    `NOTE:- You should have setup the namespaces correctly before attaching the ebpf program for our testing.`

    To attach the program you can run - 

    ```
    bpftool net attach xdp id 123800 dev veth1 overwrite
    ```

    Where the id is the same we got from `prog show` and `veth1` is the name of interface we created.

* You can see if your program is attached by doing

    ```
    $ ip a
    20: veth1@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp/id:123800 qdisc noqueue state UP group default qlen 1000
    link/ether 66:d7:2c:02:c9:c9 brd ff:ff:ff:ff:ff:ff link-netns vns1
    inet 192.168.100.1/24 scope global veth1
       valid_lft forever preferred_lft forever
    inet6 fe80::64d7:2cff:fe02:c9c9/64 scope link 
       valid_lft forever preferred_lft forever
    ```

    Notice the `xdp/id:123800` which points to an XDP program attached at the `veth` hook point.

* Now you can see if traffic is flowing back and forth.

    ```
    $ root@tcnode6:/home/dushyant/tutor/lecture-2# ping 192.168.100.2
    PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
    64 bytes from 192.168.100.2: icmp_seq=1 ttl=64 time=0.084 ms
    64 bytes from 192.168.100.2: icmp_seq=2 ttl=64 time=0.072 ms
    ^C
    --- 192.168.100.2 ping statistics ---
    2 packets transmitted, 2 received, 0% packet loss, time 1031ms
    rtt min/avg/max/mdev = 0.072/0.078/0.084/0.006 ms
 
    $ root@tcnode6:/home/dushyant/tutor/lecture-2# ip netns exec vns1 ping 192.168.100.1
    PING 192.168.100.1 (192.168.100.1) 56(84) bytes of data.
    64 bytes from 192.168.100.1: icmp_seq=1 ttl=64 time=0.089 ms
    64 bytes from 192.168.100.1: icmp_seq=2 ttl=64 time=0.073 ms
    64 bytes from 192.168.100.1: icmp_seq=3 ttl=64 time=0.073 ms
    ^C
    --- 192.168.100.1 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 2037ms
    rtt min/avg/max/mdev = 0.073/0.078/0.089/0.007 ms
    ```

* How do we ensure if the traffic is indeed passing through the ebpf xdp program?

    Well there are many ways to do so but in this tutorial we will be adding a print statement to our code which runs every time the hookpoint is executed.

    In your code you need to add a call to the print helper function like `bpf_printk(fmt,..)`. At the same time of adding a print lets change our code
    so that the hook point `drops` traffic every time. Your code might look like this - 

    ```
        bpf_printk("You Shall Not Pass!!");
        return XDP_DROP;
    ```

    After adding the print statement you can compile the sourc code.

* Before reattaching the source code we need to learn how to uninstall the xdp program and re attach new one.

    To remove the hook point you can run

    ```
    $ bpftool net detach xdp dev veth1
    
    # Verify with ip

    $ ip a
    20: veth1@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 66:d7:2c:02:c9:c9 brd ff:ff:ff:ff:ff:ff link-netns vns1
    inet 192.168.100.1/24 scope global veth1
       valid_lft forever preferred_lft forever
    inet6 fe80::64d7:2cff:fe02:c9c9/64 scope link 
       valid_lft forever preferred_lft forever
    ```

    Also to clean the previous version of our xdp program we can just clean the pinned directory.

    ```
    $ rm -rf /sys/fs/bpf/ebpf
    ```

* Now lets load the program again and see the traffic flow.

    You should now run `load` and `attach` commands from above now.

    After attaching the new program this is what `ping` shows,

    ```
    $ ping 192.168.100.2
    PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
    ^C
    --- 192.168.100.2 ping statistics ---
    2 packets transmitted, 0 received, 100% packet loss, time 1011ms

    $ ip netns exec vns1 ping 192.168.100.1
    PING 192.168.100.1 (192.168.100.1) 56(84) bytes of data.
    ^C
    --- 192.168.100.1 ping statistics ---
    2 packets transmitted, 0 received, 100% packet loss, time 1028ms
    ```

    So our `XDP_DROP` is working! but where did our print statement go.

    ebpf helpers output the print statements in the system trace pipe.

    ```
    $ sudo cat /sys/kernel/debug/tracing/trace_pipe
        ping-322689  [046] d.s3. 1900316.642586: bpf_trace_printk: You shall not Pass!
        ping-322689  [046] d.s3. 1900317.653502: bpf_trace_printk: You shall not Pass!
    ```

    There we have it, now we have ebpf programs and how to debug ebpf programs using print statements.

    You can now revert back the changes to allow the traffic and might wanna comment out the print statement because
    in real scenarios printing something for every packet is very expensive!!

    We can keep the print for debugging at later stage if we need.


### Working with ebpf maps

    What good is ebpf if we cannot get data out from it, well very limited to be honest.
    
