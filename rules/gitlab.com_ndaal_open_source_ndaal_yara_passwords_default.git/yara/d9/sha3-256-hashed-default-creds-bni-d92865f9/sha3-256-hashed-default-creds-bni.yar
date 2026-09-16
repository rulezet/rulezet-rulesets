rule sha3_256_hashed_default_creds_bni
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bni."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
    $a1="fc7f082eca25ffe62016dba0193786e8134d3a0a428adf3308c8db2a0abbae4d"
condition:
    ($a0 and $a1)
}