rule hatman : hatman {
    meta:
        author = "DHS/NCCIC/ICS-CERT"
        description = "Matches the known samples of the HatMan malware."
    condition:
        filesize < 100KB and hatman_compiled_python or hatman_injector or hatman_payload
            or hatman_combined
}