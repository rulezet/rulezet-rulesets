rule base64_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="UEFDU0xpbmtJUA=="
    $a1="TmV0U2VydmVy"
    $a2="UExNSU1TZXJ2aWNl"
    $a3="TmV0U2VydmVy"
    $a4="Uk5JU2VydmljZU1hbmFnZXI="
    $a5="TmV0U2VydmVy"
    $a6="U0E="
    $a7="UEFTU1dPUkQ="
    $a8="U2VydmljZQ=="
    $a9="U2VydmljZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}