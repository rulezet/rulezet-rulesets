rule blake2b_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61bf23f0df01a47595974a1ca3704a5fb3011d2b90813d0315e3f3dfbd4d7fbbe28bef6d0a5de61c41de419ef6211d7022930ced5988a3e1ee11cf06e51c65dc"
    $a1="4db09a7e6bdf4bc7c98f149aa63e43635da9f9051aa622585aed3cf5ad4c521717a9587c1d371e0b3c495f70077178ae7b7a1e87b0076a28dbcdb014744c63a7"
condition:
    ($a0 and $a1)
}