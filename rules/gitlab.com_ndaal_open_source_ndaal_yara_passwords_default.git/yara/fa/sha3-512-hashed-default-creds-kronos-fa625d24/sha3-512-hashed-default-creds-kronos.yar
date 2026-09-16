rule sha3_512_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e824f72155e21924ec1b3419e94d9f0d26f8f984c963e2a4a30a81758a86dfe84612c4270615517f2e29d43af696969115af2b4b06ea2806f8a9e4db3235daa"
    $a1="04c4eabf89c28c474a169a72f117e876be91027898b20c5ce0f85ca65e5f458ce16d3383b124cd238a586836113643564505a7ceea47a5b5685867489fca6e35"
condition:
    ($a0 and $a1)
}