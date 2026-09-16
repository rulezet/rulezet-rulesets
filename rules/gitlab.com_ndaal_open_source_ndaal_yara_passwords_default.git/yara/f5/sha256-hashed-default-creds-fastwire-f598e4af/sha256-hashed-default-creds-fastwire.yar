rule sha256_hashed_default_creds_fastwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fastwire."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07f7ab476bc3a83fad639d34a012cb4a5f859441f0d24c11627ca96696839012"
    $a1="ebb2df5d72722f2ac5809c0c4f006a25162d70bacea18a1a7d24fe6fb3f559c6"
condition:
    ($a0 and $a1)
}