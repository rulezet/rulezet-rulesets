rule base64_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bmV0c2NyZWVu"
    $a1="bmV0c2NyZWVu"
    $a2="c2VyaWFsIw=="
    $a3="c2VyaWFsIw=="
    $a4="YWRtaW4="
    $a5="YWJjMTIz"
    $a6="YWRtaW4="
    $a7="bmV0c2NyZWVu"
    $a8="YWRtaW4="
    $a9="cGVyaWJpdA=="
    $a10="cmVkbGluZQ=="
    $a11="cmVkbGluZQ=="
    $a12="c3VwZXI="
    $a13="anVuaXBlcjEyMw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}