rule sha512_hashed_default_creds_galacticomm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for galacticomm."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ca70567b61825bdef15255ed5841c1960e584b6488c3183e0c82e10c02f2d342cbbdc5940b2554c1e6f47b4b2263d45094a20b4aa3136c2c46f65d524b2f42b3"
    $a1="ca70567b61825bdef15255ed5841c1960e584b6488c3183e0c82e10c02f2d342cbbdc5940b2554c1e6f47b4b2263d45094a20b4aa3136c2c46f65d524b2f42b3"
condition:
    ($a0 and $a1)
}