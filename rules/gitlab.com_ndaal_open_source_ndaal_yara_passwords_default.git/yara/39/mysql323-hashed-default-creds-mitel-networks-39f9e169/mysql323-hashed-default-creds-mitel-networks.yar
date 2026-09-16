rule mysql323_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68cec90b77f54ab7"
    $a1="1e2ea1d81d71b53a"
    $a2="48d4a6bf11b81e77"
    $a3="109be9900d0cfff2"
    $a4="48d4a6bf11b81e77"
    $a5="29c83f1057f1d935"
    $a6="48d4a6bf11b81e77"
    $a7="29c83cc557f1d8ea"
    $a8="68cec90b77f54ab7"
    $a9="1363c56f0de30277"
    $a10="48d4a6bf11b81e77"
    $a11="6a77f1277b51f67f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}