rule hatman_compiled_python : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        author = "DHS/NCCIC/ICS-CERT"
        id = "fd156669-72b4-59a5-8f36-aac21d7b3105"
    condition:
        hatman_nullsub and hatman_setstatus and hatman_dividers
}