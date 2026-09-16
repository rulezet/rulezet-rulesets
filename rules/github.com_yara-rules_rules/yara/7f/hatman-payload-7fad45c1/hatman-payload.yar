rule hatman_payload : hatman {
    condition:
        filesize < 100KB and hatman_payload_int and not hatman_injector_int
}