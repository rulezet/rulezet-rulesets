rule base64_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWJjMTIz"
    $a2="YWRtaW4="
    $a3="bmV0c2NyZWVu"
    $a4="YWRtaW4="
    $a5="cGVyaWJpdA=="
    $a6="bmV0c2NyZWVu"
    $a7="bmV0c2NyZWVu"
    $a8="cmVkbGluZQ=="
    $a9="cmVkbGluZQ=="
    $a10="c2VyaWFsIw=="
    $a11="c2VyaWFsIw=="
    $a12="c3VwZXI="
    $a13="anVuaXBlcjEyMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}