rule ld_preload_backdoor {
    strings: $ = "killall -9 \".basename(\"/usr/bin/host"
    condition: any of them
}