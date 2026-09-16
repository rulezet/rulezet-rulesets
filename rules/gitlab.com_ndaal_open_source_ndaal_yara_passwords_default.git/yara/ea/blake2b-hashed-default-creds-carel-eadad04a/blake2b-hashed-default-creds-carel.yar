rule blake2b_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c26a374b47b8f8604054cd867aec29a5e95e024847fadf63eded2cfdc5c33f363ea8bc8d0ce2a14421ec384c5a112f2f20fb95a0fe568897f17477799c331ba3"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="3708456d9830844ec2928ccf88df90915b1ef08a68fdefe8e5e30b1395b416d2e320faf6949b71f8368b3410f01eab136f3d747afdc319bd7ed6314d8945431f"
    $a3="e73759ae7abe9a78f2f94bbe31e6f8d037fd33378919cdb8af11d2c38ba83449ad6abc3736b5f2f82186176acacca41be5710b7abb816d36aab4fb80d64cefd9"
    $a4="f94f97f1b9da8ff630d7eddcf58638776158e0b60a90fef9eb66a905e303b8ac05022eb1ccc4f86c4e6215a019455a059f21a0b47ab6bf7308896fed02bb79e3"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a6="f36fa1fa0b28dc239916f1640e8c0ffd4d5ddff67e3409f1b060d1afd933b1e52785f9d7f2fe862f90f94c9816a91a0d1213d446f39b02b52d775e731646deb8"
    $a7="6d0bc0da78aa75d4e3c65fa72ea422bfd1845131531059ea09862c9eb6b43412dacc856c0a19ca0248bd223477992f1b247ed6b7eacc22cdda1556fd3b3b65da"
    $a8="702d8f6f7c661b1aaa88cdb52e8acc25c7ce3ff245cb8773675dba075a645093876de67b99597b601c451a810654e781534cae068e5cda735603a24017db3cc9"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a10="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a12="3610d3ecfed1562093c4c41a7c39ccdf5652cfcb74f28639925e4ea327c26d7ba5581fd0501563a19de6465220cda144e51ade72641262a9099571376d83f1ed"
    $a13="c7f8b8a85c2184ed3ce5249dd6a8c872d19197f4ad0356bc5881d89583f3e2648a52102908523dcf59605a0d8d0e08f4f85ee7ae27a9ddcef2ca69523895da69"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}