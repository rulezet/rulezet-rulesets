rule sha224_hashed_default_creds_tumbleweed
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tumbleweed."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0e2f332d9254b64200b8b8f7406040afa06db8ed800345b03775280"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
condition:
    ($a0 and $a1)
}