rule nthash_hashed_default_creds_ca_netqos_web
{
    meta:
        id = "4MnTu2GsUK3phTIHZdcXvr"
        fingerprint = "8e66f61671192f474e0397350ee43e23d939ab863d7c4404366481a027aba656"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="757df6ad34c0daf0b4180b95558ea469"
    $a1="62e6f13811e54d953dbb254d924fd0ea"
    $a2="757df6ad34c0daf0b4180b95558ea469"
    $a3="d066c54a07a989c11597a32050eed2dc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}