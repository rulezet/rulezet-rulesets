rule sha3_224_hashed_default_creds_powerlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerlogic."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9dcc8afb1b084f071c97292291035411f30e4a38be03f063c864d686"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1)
}