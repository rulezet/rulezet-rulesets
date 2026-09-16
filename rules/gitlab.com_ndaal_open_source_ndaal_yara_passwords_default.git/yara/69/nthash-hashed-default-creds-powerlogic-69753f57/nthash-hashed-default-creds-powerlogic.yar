rule nthash_hashed_default_creds_powerlogic
{
    meta:
        id = "7m5JYEAr1xL4Exp9gW582w"
        fingerprint = "163fda78a63d33af697256a53fb1211db24aee5b3d6be82780fd5702e6cf0825"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerlogic."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e335b447c9164abcfd84fd4866311bd"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}