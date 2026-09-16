rule md5_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5dd6f624e3cde0fb8e5e6d63c85ebd46"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5dd6f624e3cde0fb8e5e6d63c85ebd46"
    $a3="084e0343a0486ff05530df6c705c8bb4"
    $a4="c57efcb10633089877fa7ca6959c572f"
    $a5="c7bb23be6d0ed7badcd1849e3c38ad41"
    $a6="5dd6f624e3cde0fb8e5e6d63c85ebd46"
    $a7="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}