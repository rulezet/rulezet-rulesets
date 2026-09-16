rule base64_hashed_default_creds_integrated_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for integrated_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="MTIzNA=="
    $a2="QWRtaW5pc3RyYXRvcg=="
    $a3="MTIzNDU2Nzg="
    $a4="QWRtaW5pc3RyYXRvcg=="
    $a5="MTk3NTA0MDc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}