rule sha512_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="de66cc38e6c9951ef0aad2a99222f315e59e87d182895a2b4300d84567225180ad6273dbb4a4a2cc356c753a0ef6f74c9f03ad9465759960009a2969f081b9b8"
    $a3="d38e60df3cafc8bba462c4c141c6b175c74a116d9f54ada21b9b17769c6629097d5049579799d56b8432ced152863164638375328f8a07e9dc54f7a4070a40ad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}