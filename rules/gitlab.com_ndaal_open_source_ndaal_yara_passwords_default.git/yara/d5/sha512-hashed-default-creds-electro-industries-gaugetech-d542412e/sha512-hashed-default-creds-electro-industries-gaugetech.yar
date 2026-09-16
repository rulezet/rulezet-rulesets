rule sha512_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a1="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a2="59167dee0ce36d119b9b945e47e95173cecb351d98ad5bc81536aa79cbeb853a8a4eb9f3cb82ad653b8ef774657623d0095daaedfb953b7aa6140588d5c6d47f"
    $a3="07385709eec96368f8e8b7a3877b35b60a6a27188bee1b4c66f260052256100710f53d39f8ad8968fefe436ca9b46fc8a6698e92513b34c60cf11ef7198d0ae4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}