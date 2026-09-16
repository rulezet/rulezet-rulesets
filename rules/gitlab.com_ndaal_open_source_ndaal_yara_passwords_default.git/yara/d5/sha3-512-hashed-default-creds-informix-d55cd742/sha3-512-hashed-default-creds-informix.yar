rule sha3_512_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f414a83225eda150b66441d061e8a0c5481846726c0d721620a3691572fc73dc759c405dcb78e47adaeb9f1fba9f378bde507a99dda232589712f35a19f095d"
    $a1="1f414a83225eda150b66441d061e8a0c5481846726c0d721620a3691572fc73dc759c405dcb78e47adaeb9f1fba9f378bde507a99dda232589712f35a19f095d"
condition:
    ($a0 and $a1)
}