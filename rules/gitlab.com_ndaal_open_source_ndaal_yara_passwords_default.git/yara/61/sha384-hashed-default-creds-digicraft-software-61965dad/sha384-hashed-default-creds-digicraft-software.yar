rule sha384_hashed_default_creds_digicraft_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digicraft_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffb4dbde5c617f19891aaa842ec0b501dc59eb65c13ee0a0a9bb7857d044699692461a6e1991fa24483d6f21f7a573c1"
    $a1="516ae2219d76b409c936cdb312451d9e282159a992dd03db87e2e094c2d09feef70cf71c008e95f4ade6153e931719b0"
condition:
    ($a0 and $a1)
}