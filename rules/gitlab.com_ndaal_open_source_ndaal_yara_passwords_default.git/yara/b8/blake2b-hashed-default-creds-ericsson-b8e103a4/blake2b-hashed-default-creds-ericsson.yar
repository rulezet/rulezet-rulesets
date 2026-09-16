rule blake2b_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a1="86dcb3b0f95abbda4b831c34271eee87f75b1ed628464796dfdca8c18edc44234119b734689182664206e4e34f1ed5483bb4a4c34cb3c7a8de709fef04cd26f0"
    $a2="6a3712e2b92f69ead391b691710a587f21fae1e7b83b94b7835344eed1c463cfe03816e61922646f7aa0b581f3ba35842b12e556b2e4e0644c0f1d1d0549a79f"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="81f783b70f8bf5cb39bafba79d696a6dc531475f6ae1b8bb819f380c852b4a776db1cb84b217c41bfd844dce41cfb790e31a4b6e12a7c12b6efb5b29eddded62"
    $a5="87480ee4a7f233177b6100e39313a05bab24bb1f8e55dc238435f0552f8df680b2e1ddbc3c02c25666cb024e710effbabdd48497842e0cf8f43127484b88e1f8"
    $a6="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
    $a7="e4fe8c2f97a24e355e600db1e13520c09c323ea214f544ff6f0f4023ebbcdd89c91740519f756c64ba094bb108b1d65183e34e24b585496c355f3aaa74574edc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}