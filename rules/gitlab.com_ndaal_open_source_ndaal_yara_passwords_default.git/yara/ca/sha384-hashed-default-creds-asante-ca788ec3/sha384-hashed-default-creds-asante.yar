rule sha384_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8013528d2f1cf3caf4afbe16d8e618f26efe259942bba110ed6a9f6ada7c3841e12dc5189334e8f8b9458cade429a34f"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="8013528d2f1cf3caf4afbe16d8e618f26efe259942bba110ed6a9f6ada7c3841e12dc5189334e8f8b9458cade429a34f"
    $a3="856a24efd702a2ca0d1685bf0f704c0d2370def2cd51fead525025a1019635740d140d2d9ab78a6a8d774ab140d74b70"
    $a4="79e841b2b010297eab94ef2c9e5a3eefd931fe6e2e589740fd2c24bbbb80d5e9e4dbb95acfe00e08d68c1dc57f36d215"
    $a5="9e9c45ab235a9f7f5fd51a3242cad3f4e9a6d72d7690e565aacc96d2508e1a4254fb10af6ccdce776cedee947cbaa129"
    $a6="79e841b2b010297eab94ef2c9e5a3eefd931fe6e2e589740fd2c24bbbb80d5e9e4dbb95acfe00e08d68c1dc57f36d215"
    $a7="ab9bd1abb1b47360f4eeda08a78839845ce1a35fef23632d59615b1f0bb5cb68d2e4db51c7e45d4c29c658c53754bf28"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}