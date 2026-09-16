rule blake2s_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d140aed39f1c5aac91290d17ff10a1994cba21340a92d741a9c0286be14013a"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d26182faed3a47e14868d1c22aff1cc5e22ff4b1fbe8962f3b334e3b35ce185f"
    $a3="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a4="8318cffddcc7b9dfc9b1a4686f607e265516940ceb8368ee3d35fa3d80395693"
    $a5="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}