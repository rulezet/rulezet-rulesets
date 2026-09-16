rule blake2b_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a1="d230428f78de6b4d82df4a3cf4ffa430b5f7ee3485107cb37cda32c5807e6a4ccd72f533b739b907fb9d410e1318f6b3e2cb0c4b39a571fce2478020cd364fa3"
    $a2="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
    $a3="f036b90815db103238fe933fe748a7ae48aa271516d127ab0962d97b403d53aecf30d3374ca2537629e767753fb6d3b421b3921838c3bd2da6ccd0043a254d3a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}