rule blake2b_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e3e4e79d5bfca6188153083b35c08113ab54f8e7ff5ddc5efa08c5a99a45a3ed4148bfa5100567abcaf06c628b7734af6813365305bd382ede48044d26f4632"
    $a1="ccfbcb2378da873484c950e554a17c117a6183167522958064980485720d09648d8c07caf60f4727f6922f6595538cf03721746142ba353161d1256693ccae2c"
condition:
    ($a0 and $a1)
}