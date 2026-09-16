rule sha224_hashed_default_creds_bmc_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bmc_software."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4393b0565dec4c736e2fde4af97d30ac7641aaee91faaa80de5cff94"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="be03e9c01bbd5f83c9abd946ad4a156bf8d8d45519fd1337f8a1a87f"
    $a3="4811d616cf90067443cd4c72fe3ef6d1d8c1ee7433f4bb4582232412"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}