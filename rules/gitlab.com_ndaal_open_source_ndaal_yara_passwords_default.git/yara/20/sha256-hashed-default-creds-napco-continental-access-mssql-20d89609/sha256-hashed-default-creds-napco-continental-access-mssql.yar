rule sha256_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a1="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a2="a2f29d1c5e994056c6e23c5bff19b6542f2aa19f0d94320ada5f17fbd34b48c3"
    $a3="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a4="d2d92511448b371f9ec196aa08fb64ef71602098494dfe3ab97d493b5ea53c89"
    $a5="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a6="b97a9c7627dc30ee7538c1f8f6bc0ca6b3471e52208e4e773c3ca3c00bfaf707"
    $a7="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a8="a2f29d1c5e994056c6e23c5bff19b6542f2aa19f0d94320ada5f17fbd34b48c3"
    $a9="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a10="d2d92511448b371f9ec196aa08fb64ef71602098494dfe3ab97d493b5ea53c89"
    $a11="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}