rule blake2s_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6eb349cccf1eafa37c8e0bca0ecbf49e9abceabef8b1eaf6945d9cd78f56fb6b"
    $a1="9ea17c5b31d81a40988a2618b43de1263b0f85da04c2d014904a72d87b79d36d"
    $a2="fe88ca356b4f5fba753dba289497f052edf54a46538658f306abfeebd79e532f"
    $a3="2d762d0c7c4a11eb6c51c497e09859defd97cf996f2b2c101b0a4fa2f0872af6"
    $a4="3ce2bf8665d90d3fe7716c31c11e2f04811d124271525816a1d4e9a7f9351728"
    $a5="91ebf18f3b02ff336c408ee9f91305ed6ff3689d7a2d543fcbcfafc275a348f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}