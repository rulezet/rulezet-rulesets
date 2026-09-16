rule blake2s_hashed_default_creds_remedy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for remedy."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7de058acc11640629e1940d47348a03f2db90eb95afff99a824d53b949a7032d"
    $a1="cbdd5921bbd6372236e3d8ffc1990c1bbf2bff8f89b35a3726dfa15c0e47e5ea"
condition:
    ($a0 and $a1)
}