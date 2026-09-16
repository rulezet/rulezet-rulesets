rule sha3_256_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a1="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a2="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a3="df134c3c5cd073714cb9e7ddc422b9c863cd7f44a8b6ac78b0afc7aee5e54011"
    $a4="f0c22f6e619581a50c7ae9ba6d14ca49a5705cbe20ac2a98d83ec813a9941a62"
    $a5="057d1b930b9c8e962bf34656a2c010888ae6a2a5fc4de074ecc8cb3bf4782685"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}