rule hatman_injector : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        modified = "2023-01-09"
        author = "DHS/NCCIC/ICS-CERT"
        id = "b939b83d-cc4a-5998-89a7-8abf8d0b8592"
    condition:
        ( hatman_memcpy and hatman_origaddr and hatman_loadoff )
}