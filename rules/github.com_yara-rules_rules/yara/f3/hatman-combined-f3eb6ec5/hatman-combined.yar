rule hatman_combined : hatman {
    condition:
        filesize < 100KB and hatman_injector_int and hatman_payload_int and hatman_dividers
}