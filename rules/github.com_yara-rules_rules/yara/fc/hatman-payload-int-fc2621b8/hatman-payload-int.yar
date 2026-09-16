rule hatman_payload_int : hatman {
    condition:
        hatman_memcpy and hatman_origcode and hatman_mftmsr
}