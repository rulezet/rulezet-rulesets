rule sha3_384_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44d48cd2d2d323d686ecb2937980dafab2f07f2e81e47c2f6fec30fd75f179242e31cdf2f00ff687679d2a8a69af8383"
    $a1="775d63c79167a78b66fe6f46b4c909b2c4175fc6ff62a43d802055ebcd347757c32ace9cd9edc8e06764b6b651be8de8"
condition:
    ($a0 and $a1)
}