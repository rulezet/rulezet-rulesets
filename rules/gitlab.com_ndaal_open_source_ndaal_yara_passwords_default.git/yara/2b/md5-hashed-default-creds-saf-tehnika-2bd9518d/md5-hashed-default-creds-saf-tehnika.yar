rule md5_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4a437999d6a7ab8dff90cdb70c7c156"
    $a1="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a2="9c7212a48ec6eeff96a3bf973eaba6e1"
    $a3="946922b258d486fa96254d7886e27b32"
    $a4="08b5411f848a2581a41672a759c87380"
    $a5="08b5411f848a2581a41672a759c87380"
    $a6="a2a69ba2bd9b5494d3ae482b82e8565f"
    $a7="4b583376b2767b923c3e1da60d10de59"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}