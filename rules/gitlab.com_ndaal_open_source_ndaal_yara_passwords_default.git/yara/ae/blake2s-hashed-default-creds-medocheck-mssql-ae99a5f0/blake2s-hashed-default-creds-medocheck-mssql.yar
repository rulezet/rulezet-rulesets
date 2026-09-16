rule blake2s_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3570b491ef3028908b17d37e63b8ed84ba81df053db5f1a7c7d6298d5c730b0f"
    $a1="152b0b5901a13eaeaa8a65f242d62700385d408d59e1946c46c3d9873e6d1ece"
condition:
    ($a0 and $a1)
}