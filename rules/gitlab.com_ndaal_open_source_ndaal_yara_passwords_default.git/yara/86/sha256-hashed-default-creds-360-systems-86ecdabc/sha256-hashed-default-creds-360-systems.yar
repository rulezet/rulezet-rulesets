rule sha256_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06c8aaa93d80a768829b6005973fa92e34612849b79910c8be8e3b006cf91c61"
    $a1="06c8aaa93d80a768829b6005973fa92e34612849b79910c8be8e3b006cf91c61"
condition:
    ($a0 and $a1)
}