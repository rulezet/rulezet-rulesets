rule blake2s_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="984d99a8c2b8f3d776cfb869cd2a91c98e2d9ba158bc159c4e8b82d0492a3294"
    $a1="984d99a8c2b8f3d776cfb869cd2a91c98e2d9ba158bc159c4e8b82d0492a3294"
condition:
    ($a0 and $a1)
}