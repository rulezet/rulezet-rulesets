rule sha384_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a9cabf2d5c387228affb7e0da802d44f309dac06b33abb130ec3412b0d9b2a8b2fe8b5c65b040e65b493039a63b6994"
    $a1="e6f8434e44ee71b6d9db1c351541b950a657e32948cce61625f3964a0e20112de8a5e5ecb7d0325283a3753f0fa66fa6"
condition:
    ($a0 and $a1)
}