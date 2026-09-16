rule sha384_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
    $a1="4f8ef699d789423ef99cfe82e7bace4663b029346936c9cdc1d596fb8bdb2e2ff243cec999d510fd0998ad07fca27c0a"
    $a2="f8f3517cf93f00d50e006c6b250f94eb69fbed4232701e9d780eb3877b75ab336add20d2484188247e43396eb1e9a36c"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}