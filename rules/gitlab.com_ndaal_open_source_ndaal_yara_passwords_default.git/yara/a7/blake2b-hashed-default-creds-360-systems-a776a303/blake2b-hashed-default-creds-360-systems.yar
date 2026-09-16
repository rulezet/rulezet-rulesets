rule blake2b_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22261d10bcffd6738bf1bd49af3e89c5735657430117fe58280df017b2c4b1970f52c94fbb44ca02d82c95c92f26e54cd8e7be5b6051ca491db604a2c9f31135"
    $a1="22261d10bcffd6738bf1bd49af3e89c5735657430117fe58280df017b2c4b1970f52c94fbb44ca02d82c95c92f26e54cd8e7be5b6051ca491db604a2c9f31135"
condition:
    ($a0 and $a1)
}