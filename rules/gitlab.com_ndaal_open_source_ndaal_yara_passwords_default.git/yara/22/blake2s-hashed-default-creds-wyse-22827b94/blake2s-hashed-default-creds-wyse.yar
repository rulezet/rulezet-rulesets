rule blake2s_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85f788510c30939dd22bb14176b615d585b0d500e3e2bc6b2b4a581d0a821420"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="e74964bf0966ab850c05e184d2b4b2c6c23f75ea831b24a2956ef66c4b64e660"
    $a3="15435fbf1b82e0ad687264f141a79e10ecc498c6b2e30d1f489e0561ba15b879"
    $a4="34c9eda7c76c43f0dbe80aa71a87c709173327ab81f6a6159d4eabee624854f7"
    $a5="708109fb58c3df709b898c9b6dbe620816bc4f91f1c089b7e0acabd2acbcc4d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}