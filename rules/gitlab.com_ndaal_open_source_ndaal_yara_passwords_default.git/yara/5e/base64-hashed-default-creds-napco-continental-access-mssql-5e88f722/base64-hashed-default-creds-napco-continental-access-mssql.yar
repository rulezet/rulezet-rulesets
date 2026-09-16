rule base64_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2lj"
    $a1="Y2lj"
    $a2="Y2lj"
    $a3="Y2ljITIzNDU2Nzg5"
    $a4="Y2lj"
    $a5="Q2ljITIzNDU2Nzg5"
    $a6="c2E="
    $a7="Y2lj"
    $a8="c2E="
    $a9="Y2ljITIzNDU2Nzg5"
    $a10="c2E="
    $a11="Q2ljITIzNDU2Nzg5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}