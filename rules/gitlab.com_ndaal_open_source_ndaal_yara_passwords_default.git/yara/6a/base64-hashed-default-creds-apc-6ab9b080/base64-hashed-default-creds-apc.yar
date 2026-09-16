rule base64_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YXBjdXNlcg=="
    $a1="YXBj"
    $a2="YXBj"
    $a3="YXBj"
    $a4="UE9XRVJDSFVURQ=="
    $a5="QVBD"
    $a6="cmVhZG9ubHk="
    $a7="YXBj"
    $a8="ZGV2aWNl"
    $a9="YXBj"
    $a10="ZGV2aWNl"
    $a11="ZGV2aWNl"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}