rule hatman_compiled_python : hatman {
    condition:
        filesize < 100KB and hatman_nullsub and hatman_setstatus and hatman_dividers
}