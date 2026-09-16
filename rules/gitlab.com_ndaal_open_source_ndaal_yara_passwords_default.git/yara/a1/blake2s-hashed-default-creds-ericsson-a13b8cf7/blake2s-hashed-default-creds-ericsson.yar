rule blake2s_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a1="c683866c00dc2ad95260337ef2b6c46b96f548fdbe2a59936535a7cb647ebd3e"
    $a2="4f38de7eea698e71df046d36abca9a5d7ce3f82f829f4b8c0f54a6334209985a"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="0b1eec1552ff1189863e2932eb76a3c3695836c36aaed8301037d8c79fdc8c03"
    $a5="8bd297185dc82427927739076bd1a19f6bc9d8a447f53813fb6e82bfaa53b65b"
    $a6="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
    $a7="143b7b8209303b61211c12812a171db7a9934b8a81066e3d8d6e3f7e50010ec0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}