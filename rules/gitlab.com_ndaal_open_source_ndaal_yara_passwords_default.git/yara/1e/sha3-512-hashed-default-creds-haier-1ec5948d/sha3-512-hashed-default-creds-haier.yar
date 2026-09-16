rule sha3_512_hashed_default_creds_haier
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for haier."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dbfc165713dc3dd994b56a7caec60d20d3edde2d54f5b49dae697b62821b6f2bffb8d08a3d3ef9e242900988af54d7ded269a55dc74ca6604e00b7785d7e4143"
    $a1="ed65f17a088f5e43ef6abda1324caa8a67bc83be94ece451b6a36bb5063c34b595deca0a1404a8401185cf6b39ec09b3855ca1db07975761e2eaa86d533e95cf"
condition:
    ($a0 and $a1)
}