rule base64_hashed_default_creds_snapgear
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for snapgear."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="MS43OQ=="
    $a1="TXVsdGk="
    $a2="cm9vdA=="
    $a3="YWRtaW4="
    $a4="cm9vdA=="
    $a5="ZGVmYXVsdA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}