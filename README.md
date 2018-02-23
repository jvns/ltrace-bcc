### ltrace-bcc

An experiment to implement ltrace-like functionality using bcc + uprobes. Give `ltrace-bcc` a pid
and the path to a library, and it'll trace all calls from that PID to that library.

Reasons this is exciting:

* uses bcc + perf events to do the library call tracing, so should be lower overhead (?) than
  ltrace, which uses ptrace (see [this blog post about how ltrace works](https://blog.packagecloud.io/eng/2016/03/14/how-does-ltrace-work/))
* this prototype is ~200 lines of relatively simple Rust and ltrace is 15,000 lines of C.

### Usage

Compile with `cargo build`. Get Cargo from https://crates.io/ if you don't have it already.

Usage:

```
# List the libraries you can trace for a process
./target/debug/ltrace-bcc PID 
# trace calls to the pthread library
./target/debug/ltrace-bcc PID /lib/x86_64-linux-gnu/libpthread.so.0
```

### requirements

Requires bcc installed on your system, see https://github.com/iovisor/bcc/blob/master/INSTALL.md for
installation instructions and requirements for bcc.

### Limitations

* Right now it doesn't print out the arguments for library calls properly -- it always prints out
  the calls as if there were 3 arguments and the first argument was a string.
* Unknown performance impact. Shouldn't be too bad because it uses uprobes but I haven't thought
  through this carefully yet.
* Can't trace more than 1000-ish library functions at a time -- `bcc` creates one file descriptor
  for every library function we trace, so it's possible to run out of file descriptors.

### example output

Here's what it looks like to run ltrace on a few different processes

#### firefox + pthread / libc

```
$ sudo ./target/debug/ltrace-bcc 16173 
Possible libraries:
/lib/x86_64-linux-gnu/libpthread.so.0
/lib/x86_64-linux-gnu/libdl.so.2
/usr/lib/x86_64-linux-gnu/libstdc++.so.6
/lib/x86_64-linux-gnu/libm.so.6
/lib/x86_64-linux-gnu/libgcc_s.so.1
/lib/x86_64-linux-gnu/libc.so.6

$ sudo ./target/debug/ltrace-bcc 16173 /lib/x86_64-linux-gnu/libpthread.so.0
pthread_mutex_unlock(140089540628720 [],0,140088461202304)
pthread_mutex_lock(140089913674096 [],140737445204276,0)
pthread_mutex_lock(140089539698712 [],0,0)
__errno_location(0 [],140737445203776,4294967295)
pthread_mutex_unlock(140089539698712 [],0,0)
pthread_mutex_lock(140089539698712 [],176,140737445204088)
pthread_mutex_unlock(140089539698712 [],176,140737445204088)
pthread_mutex_unlock(140089913674096 [],0,140089539698712)

$ sudo ./target/debug/ltrace-bcc 16173 /lib/x86_64-linux-gnu/libc.so.
clock_gettime(1 [],140737445202992,140088477396416)
strlen(140089705923984 [@mozilla.org/docshel],1,140089939581568)
strlen(140088631952416 [moz-extension://b6ba],140088631952384,4294967295)
strlen(140088469545224 [moz-extension://b6ba],140737445188512,140737445188504)
clock_gettime(1 [],140737445188400,0)
```

#### ssh + libc

```
$ sudo ./target/debug/ltrace-bcc 8540 
Possible libraries:
/lib/x86_64-linux-gnu/libselinux.so.1
/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
/lib/x86_64-linux-gnu/libdl.so.2
/lib/x86_64-linux-gnu/libz.so.1
/lib/x86_64-linux-gnu/libresolv.so.2
/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
/lib/x86_64-linux-gnu/libc.so.6
/lib/x86_64-linux-gnu/libpcre.so.3
/usr/lib/x86_64-linux-gnu/libkrb5.so.3
/usr/lib/x86_64-linux-gnu/libk5crypto.so.3
/lib/x86_64-linux-gnu/libcom_err.so.2
/usr/lib/x86_64-linux-gnu/libkrb5support.so.0
/lib/x86_64-linux-gnu/libpthread.so.0
/lib/x86_64-linux-gnu/libkeyutils.so.1

# tracing libc
$ sudo ./target/debug/ltrace-bcc 8540 /lib/x86_64-linux-gnu/libc.so.6
clock_gettime(7 [],140725000849184,94795159841440)
__errno_location(5 [],94795159841408,32)
read(5 [],140725000832608,16384)
bzero(94795159903168 [],256,94795159903168)
getpid(94795159903183 [],5,94795159903183)
bzero(140725000848736 [�.�77V],16,64952)
bzero(140725000848704 [],8,16)
bzero(140725000848752 [��p�k�vs�O.웈�(��],32,8)
bzero(94795159903168 [],256,94795159903168)
clock_gettime(7 [],140725000849280,1)
clock_gettime(7 [],140725000849184,94795159841440)
select(8 [],94795159841408,94795159841440)
clock_gettime(7 [],140725000849184,94795159841440)
write(3 [],94795159923860,36)
clock_gettime(7 [],140725000849280,1)
clock_gettime(7 [],140725000849184,94795159841440)
select(8 [],94795159841408,94795159841440)
clock_gettime(7 [],140725000849184,94795159841440)
__errno_location(5 [],94795159841408,32)
```
