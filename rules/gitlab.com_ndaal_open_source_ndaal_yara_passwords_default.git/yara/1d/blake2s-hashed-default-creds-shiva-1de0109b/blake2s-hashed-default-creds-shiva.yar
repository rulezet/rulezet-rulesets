rule blake2s_hashed_default_creds_shiva
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for shiva."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25"
    $a1="19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25"
    $a2="19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}