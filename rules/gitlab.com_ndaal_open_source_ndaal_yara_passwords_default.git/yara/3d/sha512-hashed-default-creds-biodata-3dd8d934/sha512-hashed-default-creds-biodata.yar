rule sha512_hashed_default_creds_biodata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for biodata."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="352e8d9cbd72cbe625f450060bdc0ddde545cfce4b52da9ea7d3b9823bf130f5bf9262d899f6ce756444f83f5e59331496c51699b40314c6b3757761de5496f8"
    $a1="9fcffe1acb716f176ca73cbb1cfea77b1b9c8d904171efa19b2471e293149194010fd3ca56a3b9374d19fbd441854dd92d06563b4d7a14a8a566fb76e359847f"
condition:
    ($a0 and $a1)
}