rule sha3_512_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfbe72bc0c2ebae0a0b1d44e1984fae6cba5ef2c00191bf69820d66f73af82d7279d50a16f2a47bdd939f396e2fd4af412ef7547fc87e524d7c209b27b76c3bd"
    $a1="cfbe72bc0c2ebae0a0b1d44e1984fae6cba5ef2c00191bf69820d66f73af82d7279d50a16f2a47bdd939f396e2fd4af412ef7547fc87e524d7c209b27b76c3bd"
condition:
    ($a0 and $a1)
}