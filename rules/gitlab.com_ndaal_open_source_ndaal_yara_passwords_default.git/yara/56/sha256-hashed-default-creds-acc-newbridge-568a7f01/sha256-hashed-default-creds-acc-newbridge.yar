rule sha256_hashed_default_creds_acc_newbridge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
    $a1="7f56e488201f458dcf845761b65ab0109015b569b5a5ac7809d6a2a9a0b62626"
condition:
    ($a0 and $a1)
}