rule sha3_256_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bb67652b485bf3df26bbac9cb24b281ba5670ddce7c3707b0eadc1fb26a15dce"
    $a1="25681be0e935280e34e345c5dc9132119842edce53abd47c516039e7da581c3e"
condition:
    ($a0 and $a1)
}