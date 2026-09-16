rule sha512_hashed_default_creds_sma_solar_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8a67d6a9bb3eda72d6aa7eb9361d1c46ae63805afb7ef748dbb543dab1b2b88496c4ae017b8db70e15fd65f2bf3796a6ea64ddf78da6c4d32bc213e1d9af4f1"
    $a1="072675cfeb5682aa5e6218f85c89db6469885311dabb1a68b513a2e32f3814af0d281f0e76943cc544b67b5fe2128b5f5c61f6cae91113a5d71c171168acad44"
condition:
    ($a0 and $a1)
}