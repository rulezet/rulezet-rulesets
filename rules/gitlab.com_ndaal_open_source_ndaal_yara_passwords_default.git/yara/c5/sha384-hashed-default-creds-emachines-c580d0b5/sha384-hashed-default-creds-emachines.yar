rule sha384_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d4806e5e71d6ad488f20da6a5b79c02ff89dbf2ee8df8ba2748f15c97d72b312548eddff67ae5478c197fe9b295ce4a"
    $a1="9a260a075db502a616c8540ff431e076c95172249f5123b2aa8103e3a36c13da5fe0a28c5ce9d954e1d56bb24fcf3185"
condition:
    ($a0 and $a1)
}