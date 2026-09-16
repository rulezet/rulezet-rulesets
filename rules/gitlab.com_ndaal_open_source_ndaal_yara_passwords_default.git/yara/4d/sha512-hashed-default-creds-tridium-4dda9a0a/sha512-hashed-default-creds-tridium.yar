rule sha512_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbe4316e5b19eeff6b70dd941271528e96e0d2f6fdd6f1847c459b863d50abe4b5c4942a01a97a62ac5508142951cf9988afac577a07843279b411e4d6b4eeef"
    $a1="f884b30ddbb9a9f85a5b2f8562b61650826e411f4430775b21f188e66782fbd9d0881e757be31a9fe21bf4b335f415301635af77cf69196232fe30e661f27027"
condition:
    ($a0 and $a1)
}