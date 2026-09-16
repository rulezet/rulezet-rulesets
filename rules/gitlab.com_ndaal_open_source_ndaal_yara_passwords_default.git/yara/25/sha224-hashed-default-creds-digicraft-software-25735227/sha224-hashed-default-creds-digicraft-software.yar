rule sha224_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38b388bf3e29c3feab3c7be6832061809086cf172d333dccb1e88b2a"
    $a1="4eeaf9da68e49e7f07c591625d939b7026ef96599988c16133c29389"
condition:
    ($a0 and $a1)
}