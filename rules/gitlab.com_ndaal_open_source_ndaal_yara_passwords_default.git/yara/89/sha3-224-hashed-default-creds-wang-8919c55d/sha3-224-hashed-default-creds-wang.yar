rule sha3_224_hashed_default_creds_wang
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wang."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a1db138acad008b8dddfa85f97e01642baa9b6b8fc0fbd9490da5802"
    $a1="deb029013853b98280132561f380182410ec2e006c96e6f78fc99780"
condition:
    ($a0 and $a1)
}