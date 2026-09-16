rule blake2b_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ab3ba43ea506c1a65908712926d8eb9e01e58007c08196c0fb062bd4e0c4039cec4b3a30562b8b98a96d9b489f50b4b8aa90ced4fe795eca87ca32f22ab7395"
    $a1="2ab3ba43ea506c1a65908712926d8eb9e01e58007c08196c0fb062bd4e0c4039cec4b3a30562b8b98a96d9b489f50b4b8aa90ced4fe795eca87ca32f22ab7395"
    $a2="f0952788879fd69863bedd8e86f137848c641aec6ea26bda632bf971a6e29ee7b8044b9f71d861b30d6f4dad95e3165cae9730bebdf3581b7edeab3fa660860c"
    $a3="f0952788879fd69863bedd8e86f137848c641aec6ea26bda632bf971a6e29ee7b8044b9f71d861b30d6f4dad95e3165cae9730bebdf3581b7edeab3fa660860c"
    $a4="576a277fb6154cbbd270f8de1a4c0bbda1a18732de7242c377216d459b15d26b440d97dc6ea16c26861a5f563b3695c7935adbb4531caf6c5d65aba1f8114202"
    $a5="576a277fb6154cbbd270f8de1a4c0bbda1a18732de7242c377216d459b15d26b440d97dc6ea16c26861a5f563b3695c7935adbb4531caf6c5d65aba1f8114202"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}