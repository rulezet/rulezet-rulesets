rule sha384_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a1="0494e45741bafcf54ac1157d8cb6f42a1c3d2a65f370225dbecaf49acca51239e8d2b7a73e27a84e87476bc114d8c17f"
    $a2="0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a"
    $a3="cae643d03e8f3bbd47e61afc4f8cfb7fed9657d75e539c40e83ffcf5409447610a1b130d989d0a27da7a5e3e0d3b45d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}