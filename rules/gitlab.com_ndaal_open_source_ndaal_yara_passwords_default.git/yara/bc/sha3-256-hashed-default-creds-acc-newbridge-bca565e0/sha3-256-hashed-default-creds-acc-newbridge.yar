rule sha3_256_hashed_default_creds_acc_newbridge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acc_newbridge."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a1="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
condition:
    ($a0 and $a1)
}