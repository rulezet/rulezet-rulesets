rule blake2b_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="747bcc2ae323e3e820b0c5c07162ff3e5c9e8ef500e8c8313417cc809013a058dd06a4d877c101bbb3b80fe845b35591bf3572bbd32e9bb5ac04fcb541acc94c"
    $a1="dc5a49b3fccdc43a41af195bde38728cacd9fa9ee74ea8cccd0ecd2f49ddc3618a588bee7714fa9e53efb3dafa83bf299e0bf8da3614a521d5bce313468868ff"
    $a2="cf913b1612a0e67848cb3d0f4daa418eb073c52426829d31406afb0240d6e03a28e0a0256b5b71909168087ab7d70c82d10a7deceb1bfd84d95448b06c29d7b4"
    $a3="5bcc70deb6bd2c59c087f76d8443080c0768cf8fa1f44400a80d7350e1a7b543915c44f0e5252b77189a843ca5f7f3e478149557f95644bab6243fb4915b946a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}