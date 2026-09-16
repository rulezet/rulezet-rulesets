rule sha256_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7804a56a5c7636cc05814736f44139e32920810d3bd51aa099a5df932e754ce9"
    $a1="7804a56a5c7636cc05814736f44139e32920810d3bd51aa099a5df932e754ce9"
condition:
    ($a0 and $a1)
}