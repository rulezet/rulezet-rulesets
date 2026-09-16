rule sha3_512_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="665cac670e4a335a7b818049cb1cd1d9540edf9549bb94a3b29eb38654a29561cc7bbe95d1bfeffbdc67e1e9f66fdc128f6f731e6862e7c3716b2cf160984b52"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="c52ea1cda8ad0e4b59fd94bc59e6f6dfc8c47db398a65fc814f8283fc71ac2cae9272aeef62150a4f748761272e92ed644228bc124811ec6b4a8cb7f24c33a56"
    $a3="46b6831de3414a349e105ac67c83e896716b765a044519121a08062ddf3ec86ff6b11e9c9ac697d0e515a3aba4346307793211a3127c5c1410ec2cd771d62943"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}