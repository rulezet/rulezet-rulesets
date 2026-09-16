rule sha3_384_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a3fb3710f792dd9f7d03178d60510a11d388cc9e46ecb9e013ad7ba93f8f30446ffff2c9fc4daafd6dde827b35df1c4"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="2a3fb3710f792dd9f7d03178d60510a11d388cc9e46ecb9e013ad7ba93f8f30446ffff2c9fc4daafd6dde827b35df1c4"
    $a3="a621bff9d75491dcffeb7b70227b7f2557edc8abc8afc56ddc495c1d69d54cbde78c4db85b0afd9c222cd834506e4cf9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}