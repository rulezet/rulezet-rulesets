rule nthash_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
    meta:
        id = "7Rm9kfeofWbZoMfRaDGCPw"
        fingerprint = "84a22a1fd3667524e5fd55cc7b5d8502f1f6f09611b45c7ace7e91150de7e57d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9cfcfb31c7a3c93abaa4ab823d36d5ea"
    $a1="7024cf6bfb2cb4e49f0f2ca7b88bde8d"
condition:
    ($a0 and $a1)
}