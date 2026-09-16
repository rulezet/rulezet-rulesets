rule sha512_hashed_default_creds_wang
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a79d85a7b0a5be354d18a860d1b9cd29608cb113e99943fca9590cce3b73e7e03029b9fee54830706380673be75ec143f72b19987cbd5fe0910998bbd440078"
    $a1="1063fd487f06043509190d038c46221f35fd05f779e7fabced8caf65c1295642190d63652024a37a3cc9e0f0884f276c0b7c91629eb17de07df1d3dbcfeba846"
condition:
    ($a0 and $a1)
}