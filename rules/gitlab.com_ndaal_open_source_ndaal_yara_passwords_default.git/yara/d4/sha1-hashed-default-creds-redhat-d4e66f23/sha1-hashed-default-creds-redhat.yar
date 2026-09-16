rule sha1_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a1="b15355b24ee46680adf4a63c5fb4550e28cd4040"
    $a2="22ea1c649c82946aa6e479e1ffd321e4a318b1b0"
    $a3="b15355b24ee46680adf4a63c5fb4550e28cd4040"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}