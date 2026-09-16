rule blake2s_hashed_default_creds_erpepe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for erpepe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83f790a012aa7d7bd18bc684a42ca8fd2fcca1e83eea40277b5be9cacdc0ddf7"
    $a1="379ab02ff1bf2394e78be7d3068e7cd1d9a03c924cc765c7d8b9d6dd27e85cf2"
condition:
    ($a0 and $a1)
}