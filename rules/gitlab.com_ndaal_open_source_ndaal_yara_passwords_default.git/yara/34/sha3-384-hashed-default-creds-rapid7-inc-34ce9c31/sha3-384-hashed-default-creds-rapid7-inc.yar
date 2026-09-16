rule sha3_384_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c89a873b7a3162409f4bb6a49c98e49396537fca7ee25469b0a25c298d91b08077f682f63a121d92ffe209b2543e439"
    $a1="5c89a873b7a3162409f4bb6a49c98e49396537fca7ee25469b0a25c298d91b08077f682f63a121d92ffe209b2543e439"
condition:
    ($a0 and $a1)
}