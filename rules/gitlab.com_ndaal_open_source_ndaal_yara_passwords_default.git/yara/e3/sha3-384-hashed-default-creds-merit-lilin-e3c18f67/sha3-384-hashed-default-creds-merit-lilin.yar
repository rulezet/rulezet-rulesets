rule sha3_384_hashed_default_creds_merit_lilin
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for merit_lilin."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="843409037b38a6c5bc0bf82fc73a738806c5a80a2c35e21cb14c05d070f485d2bac684859de64e4e286e006b650e54ea"
    $a1="60a5a8e40df89059db62247604a9e5d9707d1176cdcf4040a9d6883f2ea3ef1828b2023d1558c1b21a5296ab9fcc385b"
condition:
    ($a0 and $a1)
}