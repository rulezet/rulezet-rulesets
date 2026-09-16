rule sha3_256_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="951d867bf1ede717ac94254d5fd45b6133471ebe860eb8583648ca3f89c8ed79"
    $a1="951d867bf1ede717ac94254d5fd45b6133471ebe860eb8583648ca3f89c8ed79"
condition:
    ($a0 and $a1)
}