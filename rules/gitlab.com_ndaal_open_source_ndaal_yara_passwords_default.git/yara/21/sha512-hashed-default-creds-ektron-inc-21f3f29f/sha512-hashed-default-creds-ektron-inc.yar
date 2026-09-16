rule sha512_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76a447de1f4d7c97c4650376d6f7f805bf1f730a60cd67166bcfe7254a4ee3010c0e4b7dc25e1d3e6c948af107874b4b3214b22bd638d22cfaa3bdc2c7ffb05a"
    $a1="76a447de1f4d7c97c4650376d6f7f805bf1f730a60cd67166bcfe7254a4ee3010c0e4b7dc25e1d3e6c948af107874b4b3214b22bd638d22cfaa3bdc2c7ffb05a"
    $a2="4aa4754c637fa58fd50afcae0a73d211b27cde13a3adc04c419689f51d13c2ddac1a9bb3af992f7f998ddab9f6930de99f8ee9ef7778da33c924df367519b48d"
    $a3="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}