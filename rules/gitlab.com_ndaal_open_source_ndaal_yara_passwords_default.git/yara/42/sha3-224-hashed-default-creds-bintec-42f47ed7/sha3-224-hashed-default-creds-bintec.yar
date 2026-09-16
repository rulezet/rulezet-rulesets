rule sha3_224_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e37a7ca5f62f4c86e3dc11b460db893fac7798465f5cb9f4b2f2e3ee"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="80b35885f86c51945439626b539eb283e6fada204e33fcf521201b51"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="0b1d5def4f0257158dc6022349b17d0f19a18bed83b32f164e03a116"
    $a5="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}