rule sha3_384_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="253901e35798fc58539cd8a8d6558135b00ed1bc708b4e2a53394097a4cb4dc9a28ec019bf5f13dac2811678dd963c34"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
    $a3="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}