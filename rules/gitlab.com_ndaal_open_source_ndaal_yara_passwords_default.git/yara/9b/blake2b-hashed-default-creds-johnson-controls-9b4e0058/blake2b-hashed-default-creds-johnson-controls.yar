rule blake2b_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2815b777b7db227ba97c90a15ec8f2d9bfebe7ccb665bc6e582c4871adb9a7c91c0fe6ec775393f98b9d872cc41ef773ab2f3697bfebd82a43ae13083e695a3a"
    $a1="99cf80b12673ee366d20c78d4b3c4eedb12f7877e5f8a58dbe60a08ccf9e6ba3cf109751fc8de14c49e7c74487f7b3ba302c6756ca5ebf4e0c24636b573690b0"
condition:
    ($a0 and $a1)
}