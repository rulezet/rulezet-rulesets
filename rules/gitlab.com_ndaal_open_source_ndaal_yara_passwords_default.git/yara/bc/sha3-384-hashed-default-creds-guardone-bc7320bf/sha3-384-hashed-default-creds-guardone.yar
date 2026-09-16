rule sha3_384_hashed_default_creds_guardone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for guardone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b58da853115eb388c5e9210e21fbf56aa8aff19a5b4a03cb989afdea87eb01db936947b1a57cb25c1897d56f3596ab28"
    $a1="5f0168368ba48f6fd4464d8fc0ec4f21bba83fa2f7de57b0b6c2bcd6bde90185fc93a6a44ca59c4d6e15c44e4ab8a60a"
condition:
    ($a0 and $a1)
}