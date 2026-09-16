rule sha256_hashed_default_creds_us_robotics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotics."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
    $a5="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    $a9="2b505597daa736f13c2910c260e8deb1af3b20ffe375eb5e01a003e92f541db9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}