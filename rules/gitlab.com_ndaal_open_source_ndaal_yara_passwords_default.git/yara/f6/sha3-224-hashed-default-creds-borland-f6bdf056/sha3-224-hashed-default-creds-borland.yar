rule sha3_224_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4c5d5cc94bf3c575ce0591c10afdb793d2bcef8f549ecf1331c24fa"
    $a1="fbb6e56767a076fe0bee77533eac6860e3150c9bae0b42de1f077498"
    $a2="f4c5d5cc94bf3c575ce0591c10afdb793d2bcef8f549ecf1331c24fa"
    $a3="4e1c1e4708158e40de34275fe8ff608c7e3c9831bd9e46d055e34110"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}