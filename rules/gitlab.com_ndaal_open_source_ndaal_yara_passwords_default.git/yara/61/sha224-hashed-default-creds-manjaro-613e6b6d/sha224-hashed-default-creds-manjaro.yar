rule sha224_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="750c9dedf0e64aa63a3e1332d76af11503417b8a0ecb137012856f37"
    $a1="76e197434d1b65e3440915ef1930aad0702e34dd355e419af3aea28f"
    $a2="60fff09a536ae771070ff0e7cbe146e7857b6f0ebd21f57811a47b4e"
    $a3="76e197434d1b65e3440915ef1930aad0702e34dd355e419af3aea28f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}