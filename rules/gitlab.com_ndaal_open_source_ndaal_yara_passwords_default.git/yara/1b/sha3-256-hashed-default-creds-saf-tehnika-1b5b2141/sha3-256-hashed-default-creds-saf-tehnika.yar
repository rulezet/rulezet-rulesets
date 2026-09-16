rule sha3_256_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7823ddc39cf0edafe9b75fd43d026530fd370a94e9a1d6a7bf3620a8020af9e4"
    $a1="bdb3f8add40dad8b96492731a523f85358d8f3c3ec6458ba9c3aeb02fe8d48ab"
    $a2="09e5aed71673f3e3c29c4821dbab77c91f5b641f1213cb5866c3a6c487bd17ce"
    $a3="130b7c6c9040885eb45c54641120182aa82f6d562f777c320cac42bea954c34b"
    $a4="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a5="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a6="29f1138ca2ea0780312f640305c1aa9116ce32c3774d3fa5370efc29953d3400"
    $a7="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}