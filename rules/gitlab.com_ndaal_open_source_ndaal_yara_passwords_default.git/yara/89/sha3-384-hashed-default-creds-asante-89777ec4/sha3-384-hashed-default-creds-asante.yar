rule sha3_384_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87290571eba3eba6aec4faa6736368a75ecb90fc784d476cd8f5c3ea877a5cd9f0868dbe5cce3dbbd65b06a47cf7c302"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="87290571eba3eba6aec4faa6736368a75ecb90fc784d476cd8f5c3ea877a5cd9f0868dbe5cce3dbbd65b06a47cf7c302"
    $a3="05de7187b529f77320118b614d697fd59004745c2993e9e827e78b02049458c9afb928d19c5e7f2917c9d57c9b841ad1"
    $a4="5eef2e4f10c050e9758d64fcee1c10e5b83de22882ad412e671e914825a8c81c80e8af16c02e797a8d2c31cfaea51d86"
    $a5="2d2883c76a749712765314a029706a65cc6cc6ebed4a391a8f9b094a7c005c2f6df6984f8470cb99e6e1c3374fefe6a3"
    $a6="5eef2e4f10c050e9758d64fcee1c10e5b83de22882ad412e671e914825a8c81c80e8af16c02e797a8d2c31cfaea51d86"
    $a7="b434a0786144a999f291f53fb0734331b6f2fc4bda164afc4e33b2d1dcd02078f92510a0d54436c1c1da86940878ccac"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}