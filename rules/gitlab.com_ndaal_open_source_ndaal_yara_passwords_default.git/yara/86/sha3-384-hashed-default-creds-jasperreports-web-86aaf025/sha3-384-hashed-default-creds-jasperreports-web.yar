rule sha3_384_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c02019ec9e70d96b6adbc7c2ad0848a01034cb1eaff489ea690c04a14af8c729bd215c8c39f65ab98fc1ad4adbcfffc"
    $a1="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a2="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
    $a3="f0ccd58f8e5f56aaeb2f593e41428e96730fd7819d6b1ca53fe43f68ffcd11a941729d438e4c020a954149bbcfe8ca87"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}