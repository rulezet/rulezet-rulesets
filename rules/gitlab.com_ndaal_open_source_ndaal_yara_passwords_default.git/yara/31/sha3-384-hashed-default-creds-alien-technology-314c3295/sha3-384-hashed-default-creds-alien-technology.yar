rule sha3_384_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
    $a1="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
    $a2="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}