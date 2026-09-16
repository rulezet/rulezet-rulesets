rule sha3_384_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db71b81ee66ca19c04e7b1804d1dad4e31ad0f3dab39c01753305fb12d28e8572388deeed7b1f1b898ef3c418942f676"
    $a1="40a1f312227d75d654ad1c94bb8dd124c47a854ba35ba082885180e31f67760fa4e152c10bdfb838101a04b6cc9f35eb"
condition:
    ($a0 and $a1)
}