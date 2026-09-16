rule sha384_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f1f3f46cd24860be8274a1bc432301bbe3c4b710ef1f595500e8ae4c012d46611760233b7513e8afa75b8d7b58dab25"
    $a1="fe8233906c40a7f03d90c280915dc63c4b173c7f7acb1450b2c06086cb347aedcac428d8ae7aee4068443f72dfac0e36"
condition:
    ($a0 and $a1)
}