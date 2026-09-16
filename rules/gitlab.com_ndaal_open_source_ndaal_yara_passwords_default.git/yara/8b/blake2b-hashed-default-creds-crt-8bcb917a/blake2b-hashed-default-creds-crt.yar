rule blake2b_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="089ad4a1f4542a5c787202aca7d2c866d642fea04b2095079516e854b279cc873c8954526ed54491e4af8ce4f9b9169b41128bb49969797c77fbeb99782b94de"
    $a1="09aa5f344a91d156cdeab4c5705a35bb5cec4eba1120b1e3d6041090c4703be0a7de8276e496824d0001b627732edd236a50023c658731bc0a201e792b15f16e"
condition:
    ($a0 and $a1)
}