rule blake2b_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="33ace3eb11c517be804f516ab407838b51c6eb5baff3203ce3a320b6750bd1bcbf7091092555a332abc4d467ef3c13fcd9ff5312aa0036b98ff1b29774d55f4a"
    $a1="64405c714a7b80967205d987ab2fc9c81e58c5181af6423762574b141760b8d44a4d391516d16c32c877a9506036f99b8edfacaffe93a678d20fda239f557120"
condition:
    ($a0 and $a1)
}