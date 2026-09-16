rule hatman_injector : hatman {
    condition:
        filesize < 100KB and hatman_injector_int and not hatman_payload_int
}