rule sha3_256_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0130b53e1a0a83b2181436d6fb302bb1670580273f45ebcf788462a53d658b"
    $a1="7260a950618522ae4eaf0088954ae4428c75f5b9a6daca8bcad8aea5bc8979ed"
condition:
    ($a0 and $a1)
}