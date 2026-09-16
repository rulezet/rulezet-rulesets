rule sha1_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a1="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="098d2c8ea4f769376ef7dac9730214dfd388bc05"
    $a5="efe3c5e47c595a2a47b605d35134031b6148d848"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}