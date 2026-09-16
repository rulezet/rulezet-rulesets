rule mysql323_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c22309e255eca6a"
    $a1="43e9a4ab75570f5b"
    $a2="6384e9056103be5f"
    $a3="43e9a4ab75570f5b"
    $a4="1a486e7929011a28"
    $a5="1a486e7929011a28"
    $a6="0a5384c92a827813"
    $a7="0acaedaa7baad4c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}