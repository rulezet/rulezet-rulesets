rule hatman_injector_int : hatman {
    condition:
        hatman_memcpy and hatman_origaddr and hatman_loadoff
}