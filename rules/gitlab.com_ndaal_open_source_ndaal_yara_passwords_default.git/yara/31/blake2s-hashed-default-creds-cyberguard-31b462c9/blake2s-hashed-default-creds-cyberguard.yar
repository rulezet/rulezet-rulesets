rule blake2s_hashed_default_creds_cyberguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberguard."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c1897f0651666ab1d2fe4bdf089f76ff072d748fd1c401c0d8291643e7b6bba"
    $a1="3c1897f0651666ab1d2fe4bdf089f76ff072d748fd1c401c0d8291643e7b6bba"
condition:
    ($a0 and $a1)
}