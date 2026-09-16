rule sha3_256_hashed_default_creds_raspberry_pi_foundation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_foundation."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbe01278f00e2de65533a93974896715ca37b4b2a915db69d9f234555e7342b9"
    $a1="7d9605848f19017dc0bc40e0d0c32c4b2238e31713945f8b797347ae29039ec3"
condition:
    ($a0 and $a1)
}