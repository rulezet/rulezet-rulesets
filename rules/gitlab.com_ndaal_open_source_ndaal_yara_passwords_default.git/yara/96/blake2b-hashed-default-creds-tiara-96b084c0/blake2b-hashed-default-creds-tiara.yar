rule blake2b_hashed_default_creds_tiara
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tiara."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02eb805bb6f27654bd1ed7d9879e2736c8a759a71944db2081828472450bdd998187002ca1f1f8395365699204e3424158e648016a16484461fb97102c5f5e85"
    $a1="afd1f93f57cabb1de66da1abd14628d2ae2bf9b2c5c5eb496dfa19c9ebf6153b0ffeb01b96aade0dc718d91307aec78a124ca450b66070ce146232d402843b9f"
condition:
    ($a0 and $a1)
}