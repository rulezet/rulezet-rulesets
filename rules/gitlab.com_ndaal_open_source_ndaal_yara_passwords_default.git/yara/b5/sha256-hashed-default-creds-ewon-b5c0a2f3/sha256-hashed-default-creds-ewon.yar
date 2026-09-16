rule sha256_hashed_default_creds_ewon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ewon."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86f65e28a754e1a71b2df9403615a6c436c32c42a75a10d02813961b86f1e428"
    $a1="86f65e28a754e1a71b2df9403615a6c436c32c42a75a10d02813961b86f1e428"
condition:
    ($a0 and $a1)
}