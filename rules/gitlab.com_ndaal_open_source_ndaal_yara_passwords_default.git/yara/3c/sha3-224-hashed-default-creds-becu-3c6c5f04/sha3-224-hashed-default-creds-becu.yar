rule sha3_224_hashed_default_creds_becu
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for becu."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="20f0181b0270a5dbef694a7ae73caf821d35138e998cb40e59a3d422"
    $a1="7e610c66661efb5363535db0f09e02ed10ed3db0468a1807e4593587"
condition:
    ($a0 and $a1)
}