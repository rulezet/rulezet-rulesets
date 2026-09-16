rule sha512_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="adfcbddb386b6488dadfb43444abcdd8ec6f96cff59bcc2b412ec3d6a813967de3a11c35d7ad334fda9ba135813bba40ce0dd41abd7014559fcc2de90884f5ea"
    $a1="adfcbddb386b6488dadfb43444abcdd8ec6f96cff59bcc2b412ec3d6a813967de3a11c35d7ad334fda9ba135813bba40ce0dd41abd7014559fcc2de90884f5ea"
condition:
    ($a0 and $a1)
}