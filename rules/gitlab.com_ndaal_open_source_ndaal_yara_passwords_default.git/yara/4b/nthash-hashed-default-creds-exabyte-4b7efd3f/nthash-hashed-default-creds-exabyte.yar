rule nthash_hashed_default_creds_exabyte
{
    meta:
        id = "IYDKnLvI6z01z4zb5hzFc"
        fingerprint = "a4f27ba795e8dcbcea5246fa209f53f4ee2d49c8a5dc05f2fed38d165262c5ea"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ece1717c6e5a0a3e330fc731837604d4"
    $a1="4481b934fc9cad79cb0f5295fa8cfc98"
condition:
    ($a0 and $a1)
}