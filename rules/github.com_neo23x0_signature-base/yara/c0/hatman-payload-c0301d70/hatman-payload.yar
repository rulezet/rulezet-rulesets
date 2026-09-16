rule hatman_payload : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        author = "DHS/NCCIC/ICS-CERT"
        id = "9ef57fca-a536-5937-8510-b410f735a73e"
    condition:
        ( hatman_memcpy and hatman_origcode and hatman_mftmsr ) and not ( hatman_origaddr and hatman_loadoff )
}