rule sha3_256_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f97ff344ca030efffcdfdbb49eb4dc63ba28b63ee98cebc68a4655f790b486be"
    $a1="f97ff344ca030efffcdfdbb49eb4dc63ba28b63ee98cebc68a4655f790b486be"
condition:
    ($a0 and $a1)
}