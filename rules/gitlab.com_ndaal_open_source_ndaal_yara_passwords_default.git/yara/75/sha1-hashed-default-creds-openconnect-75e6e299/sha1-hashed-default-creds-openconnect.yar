rule sha1_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a3="01c8267a0c30f7796fc2ee0a35aec585ace242e8"
    $a4="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a5="6f372c90822f7de721f3e6edc42653a746e81d90"
    $a6="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a7="0e0a61c867616eef145bca3653bbd02406032dc1"
    $a8="9c7c944ba8e134bc69a910180d62952c99050f8f"
    $a9="875a8f2f42c570f5f4ea7bfd154f582bcf95673a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}