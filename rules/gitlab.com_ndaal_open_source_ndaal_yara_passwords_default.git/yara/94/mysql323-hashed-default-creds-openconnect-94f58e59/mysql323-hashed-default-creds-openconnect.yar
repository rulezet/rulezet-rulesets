rule mysql323_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="70b2e5a30e6382a9"
    $a1="43e9a4ab75570f5b"
    $a2="70b2e5a30e6382a9"
    $a3="16335ff7796b3e75"
    $a4="70b2e5a30e6382a9"
    $a5="6401910e02aca0a0"
    $a6="70b2e5a30e6382a9"
    $a7="5db42baa3b16472b"
    $a8="70b2e5a30e6382a9"
    $a9="133909766fbd3413"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}