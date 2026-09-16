rule sha3_224_hashed_default_creds_corecess
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for corecess."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62bd8c026fddbbd714abc21d8cfce219b209e9089baeb6b65a749fda"
    $a1="62bd8c026fddbbd714abc21d8cfce219b209e9089baeb6b65a749fda"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}