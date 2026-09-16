rule sha3_256_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54216db276e2b24855d598ee1bebd7fc545ea567fa393cfe74c5a1f860e18039"
    $a1="5cf0e6a4583e94fa3479fad7aefd3ef63684423006fa29bd458636b94ee95247"
condition:
    ($a0 and $a1)
}