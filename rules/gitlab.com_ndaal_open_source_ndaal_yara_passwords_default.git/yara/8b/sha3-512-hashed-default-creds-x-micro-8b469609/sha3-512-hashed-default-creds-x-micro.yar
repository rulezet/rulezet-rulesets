rule sha3_512_hashed_default_creds_x_micro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for x_micro."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
    $a1="a5cb39ab7a85e70d39ae78b734b0f42660126100c6d458fdd3f8e6b20ab8f73b2db2a02a0ca8d38d40b6b2544be6491243703c5770cbce76385c2e3a9c791f36"
    $a2="3921e2f50eb457822d01a770d4a6a8dfb31483ae01f60056c64f4bbe9989e5a99c9e51201294254be63ae22cc194f1889cff8f4e3f491c6d2307e41ce1566b02"
    $a3="3921e2f50eb457822d01a770d4a6a8dfb31483ae01f60056c64f4bbe9989e5a99c9e51201294254be63ae22cc194f1889cff8f4e3f491c6d2307e41ce1566b02"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}