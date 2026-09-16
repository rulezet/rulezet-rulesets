rule nthash_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        id = "4SdKBEZh5fu7aZqvaQjmYh"
        fingerprint = "c363c773db07116789113419ef844f9a8e3d16922e0c2c33b8660a88bc6c9a97"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2c124114b8e5d74e3e01bcb6620a1f4d"
    $a1="f6042fd4c5c2578c33347b332d4a6c07"
condition:
    ($a0 and $a1)
}