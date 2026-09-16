rule sha1_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e09771b3cf9fdfceeed0f06bb188e7a2d434e134"
    $a1="e09771b3cf9fdfceeed0f06bb188e7a2d434e134"
    $a2="6401561d8326540f8d1be2112081432d8ddf62da"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="b8fad891d4314ddc31d382ce6a48bd3e3ff135b7"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}