rule sha1_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a1="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a2="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a3="4899a849f6a3cee79e2ad5b7dd93d0a7f276d493"
    $a4="bada309e51e6ea60a1dd20fc3b9173a197ed06f5"
    $a5="bada309e51e6ea60a1dd20fc3b9173a197ed06f5"
    $a6="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
    $a7="8e67bb26b358e2ed20fe552ed6fb832f397a507d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}