# gurt

a modern, colorful, and feature-rich ping utility written in c++ that can simultaneously ping multiple IP addresses with comprehensive statistics and beautiful color-coded output.

## features

- **multi-target pinging**: ping multiple IP addresses simultaneously using threads
- **color-coded output**: each IP gets a unique color for easy identification
- **advanced statistics**: min/avg/max, median, percentiles (25th/75th), and standard deviation
- uses proper ICMP echo requests (not TCP connections)
- set custom ping intervals
- real-time latency measurements
- shows comprehensive summary at the end

## quick start

### prerequisites

- c++ compiler with c++11 support (g++, clang++)
- only tested on mac but should work for linux
- root privileges (required for raw ICMP sockets)

### build & install

```bash
# clone or download the project
cd gurt

# compile the program and set up root permissions (one-time setup)
sudo make install
```

## build commands

| command | description |
|---------|-------------|
| `make` | compile the program |
| `make clean` | remove compiled binary |
| `sudo make install` | set up setuid permissions for current directory |
| `sudo make install-system` | install to `/usr/local/bin` system-wide |

## root permissions

**important**: this utility requires root privileges to create raw ICMP sockets.

### why root is needed
- ICMP ping requires raw sockets
- raw sockets are restricted to root for security
- this is the same requirement as the system `ping` command

### security notes
- the program drops root privileges after creating sockets
- only socket creation requires elevated permissions
- uses the same security model as system `ping`

## usage
#### note:
if built with `sudo make install-system`, then you can run anywhere with gurt
```bash
# ping a single IP
./gurt 8.8.8.8

# ping multiple IPs
./gurt 8.8.8.8 1.1.1.1 208.67.222.222

# custom interval (2 seconds between pings)
./gurt -i 2 8.8.8.8 1.1.1.1

# ping same IP multiple times (useful for load testing)
./gurt 8.8.8.8 8.8.8.8 8.8.8.8
```

### command line options
```
usage: gurt [OPTIONS] <IP1> [IP2] [IP3] ...

options:
  -h, --help         show help message
  -i, --interval N   set ping interval in seconds (default: 1)
```

### example output
```
gurtyo git:(main) ✗ gurt 10.2.31.1                      
interval: 1 second
target ip: 10.2.31.1

yo 7.469ms
yo 3.538ms
yo 4.501ms
yo 6.326ms
^C

received signal 2, shutting down...

--- gurt yo summary ---

10.2.31.1:
  4 gurts, 4 yos, 0.0% no yo
  round-trip min/avg/max = 3.538/5.458/7.469 ms
  statistics: p25=3.538 median=5.413 p75=6.326 stddev=1.533 ms
```
## uninstall

```bash
# remove local binary
make clean

# remove system installation (if installed system-wide)
sudo rm /usr/local/bin/gurt
```