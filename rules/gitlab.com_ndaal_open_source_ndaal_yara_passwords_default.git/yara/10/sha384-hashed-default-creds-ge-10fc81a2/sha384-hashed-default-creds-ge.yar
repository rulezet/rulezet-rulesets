rule sha384_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7ed8b88fdda5ad3b407efa1d7770782465225747d724de2919032054f4af875e5459f01f50570be0b4d16b3ab6a55d6"
    $a1="e4043b0a496de333decd2f4e73aa8b10120ae24fa86ed48879ee4beeeeca9631b7cdd17d668187780c8d23db8d40e609"
condition:
    ($a0 and $a1)
}