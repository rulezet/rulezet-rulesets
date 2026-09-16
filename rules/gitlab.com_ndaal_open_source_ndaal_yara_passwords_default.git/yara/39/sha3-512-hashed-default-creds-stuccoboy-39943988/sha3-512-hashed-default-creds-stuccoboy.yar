rule sha3_512_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fef5c52d529b768b94d6f78cb8e74328556bc7fe6242ff051ce60af1117bc9ff1872303067fd1d0fb6735223f7bd00ed59c58631dd246d8fd724e745e2756ed6"
    $a1="d588bd9e7ce98732c4de05d9a3f4304a3b85658ae5a5b51c9fbfe29155ef6da9d42fea20e2c4017eecd3dff440cbc68473e35e56aee47371645955e22fed24cf"
condition:
    ($a0 and $a1)
}