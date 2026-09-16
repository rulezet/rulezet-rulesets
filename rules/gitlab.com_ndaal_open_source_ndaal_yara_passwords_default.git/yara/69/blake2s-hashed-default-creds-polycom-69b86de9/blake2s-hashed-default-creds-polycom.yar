rule blake2s_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
    $a1="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a2="0894548f2f7123ad7209d8bcbb1fc4b3bd06b394ad0f1f8285baf4b978d63f30"
    $a3="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a4="bda6e6fceb2a94ff97a0720b0202b3f1d31a7e241ec767afc18464da14c7edce"
    $a5="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a6="5e328fa3b17ebb32cf0382d3012b005263eb26333ea6fe9c7cbf83e3558df98e"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="3f6be9d5ff390796fdf62e19e43cc62cc8d00458d3887098b40f413f56b87fbf"
    $a9="1a0171ec046b5d5f7997e50a84ea78da4f1ce97ba57ec4c0e9983e21ac00941a"
    $a10="1d9d8b9a458754c6f38ef1659a4b869ffd939dd25474b0c1677b36ace49dd37a"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}