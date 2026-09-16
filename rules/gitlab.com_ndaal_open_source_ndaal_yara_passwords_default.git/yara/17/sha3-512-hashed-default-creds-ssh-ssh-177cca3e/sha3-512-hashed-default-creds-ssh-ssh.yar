rule sha3_512_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7df725d7cdedc20832ba15a82a093cf057fb949f4ffd411ebaf0eb5433e2b076a62598b45f5fd356d5877ef736d7dca187278b3b419179d4a42257ef600109c"
    $a1="c7df725d7cdedc20832ba15a82a093cf057fb949f4ffd411ebaf0eb5433e2b076a62598b45f5fd356d5877ef736d7dca187278b3b419179d4a42257ef600109c"
    $a2="d8cb68884b73300f1d449f3a207d9bcb734683bceca68e22897a1fe793344162fbb0359d89da2b12ece7664715f092e7c24274c8a69ce9cb5ff0b865aa425338"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="830da7fdae27f65e0604953d955bdc20f007c6cbbb2a807cae31d88cef2403516d6c5f7a656f47eafc376cf37127fa824e115f7b34db333904354490edea6292"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}