rule sha3_224_hashed_default_creds_gonet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gonet."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed683fef3064c52ff9d511bfb2145a274599082e324499a238d71038"
    $a1="7727feb00ed156546949bc0e39909c4011b7d6153de06cd656686542"
condition:
    ($a0 and $a1)
}