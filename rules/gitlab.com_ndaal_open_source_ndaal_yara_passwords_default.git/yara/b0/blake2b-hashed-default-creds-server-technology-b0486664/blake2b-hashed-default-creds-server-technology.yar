rule blake2b_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa224afe871f55b53ecab25ccfefc9c72b3ded0df405356b1678b3479547b9bcb37cbc7e4dfff91851122e9173ff6d3438a0a7e6913222e6d9508dcd54d758f5"
    $a1="003d79c3d6f9e9308a460b87174a2e815fe38c1cba5c9e1d1b4a3b71e1cd0eb5a189920969348c7e47cec65b5ca9a735ccf732490a87a71c3dea8c427bde64d3"
    $a2="9740babae0ee30787fec84991aa058a71139a47d4ce7632727e55e883dcd9297feec6a3b2cfdc563b5b1f0fb230e5f06b82778f62f4ca8de7f764f292c86cb9f"
    $a3="d314ec522eb96a936055fc0faafc1f07a475c23e49d9a88d84190a1bea64a2d5a8aca75afc8c9b60b93bab3e704b6a23f2dac5f872573be2b63b3a26ec554572"
    $a4="6184f589e4c67678ea3fdf1b45882167563734f570a92bcc3c4edc652eebf9653dbe81adb304d6399ee299b20998ea9960849327b3ede29bb5397c47ed164321"
    $a5="c8b575db946e92fcaa02dd7f42c529925d6ec0a380c800650a95d50d11bfce208521b13d2328cb28b96eef7d3a81cd7fa2101132522be1d5d7165aec0e61ac79"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}