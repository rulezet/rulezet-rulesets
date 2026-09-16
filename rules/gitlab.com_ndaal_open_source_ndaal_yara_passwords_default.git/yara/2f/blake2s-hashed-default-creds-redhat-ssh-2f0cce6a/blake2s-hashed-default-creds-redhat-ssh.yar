rule blake2s_hashed_default_creds_redhat_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a3="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
    $a4="ae3b60e36575f4b166ba8737078140a43a64e58905d9a502ec2f2587a7079307"
    $a5="557ef3933d2c109af7ddb908c97d25f88a068af4bf1a346403ab0e0f309b1a82"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}