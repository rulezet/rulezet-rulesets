rule blake2s_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8cb1f679eab1704dae0706209187dda9814c1e64e253f5d392b48094ba2326a6"
    $a1="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a2="2b6960b1810a43c4d841e7459f71b4612f67f6e0dcb6db5c2da82b245c3cb544"
    $a3="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}