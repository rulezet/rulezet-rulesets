rule sha512_hashed_default_creds_coyote_point
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for coyote_point."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2cae3cff3a4fd172c2ce46c32e90ddc04e8d16dd44dea71ef96ee980d899ef0b3d664142c7a9620949d5510e91b6fea4f7b4f2634f046893319b9720ea38d152"
    $a1="ace0d6400bf7feee4e0a2a0d60dea2585bef845ed948ab153dd54de0433406c4f36e26e627cd3c3b790908bfd879f31a92a8723b0b416326f017e9ebeaddbd7c"
condition:
    ($a0 and $a1)
}