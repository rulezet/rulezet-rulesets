rule sha3_512_hashed_default_creds_schneider_premiumweb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_premiumweb."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
    $a1="f8059e95f875706acbbbd37924172b947f399d5ff4adae42babb986e4589b456b3f1e69517496db9276a559b7ee106ee54a367a28518e6bafa696736927b0c92"
condition:
    ($a0 and $a1)
}