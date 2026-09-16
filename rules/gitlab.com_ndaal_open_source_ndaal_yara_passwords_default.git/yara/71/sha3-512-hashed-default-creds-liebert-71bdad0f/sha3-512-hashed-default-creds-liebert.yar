rule sha3_512_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
    $a1="9d95c357580759ddd936324a52d9027763edaea366bf6bd2a2ed39708ca5fbbd52001c38ce4e8d5f86f44faade09a576775d02c3c0876edf998d5b5aee9069c4"
condition:
    ($a0 and $a1)
}