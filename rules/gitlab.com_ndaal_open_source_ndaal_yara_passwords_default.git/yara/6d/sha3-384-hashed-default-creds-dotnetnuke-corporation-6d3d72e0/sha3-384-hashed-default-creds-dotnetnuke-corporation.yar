rule sha3_384_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="419782da9de8f9546cb015f8b2b56708f278c1873e9e265a5a75990e518b852a2061cc54ef843065d3b84d171b6d474e"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="5f66cdfd90f5e779e36b0f0713f2e038860b455fc4d43313b039fd752ff54c49ac296984f9a80d96436b9cfeacc01432"
    $a3="5f3d970704a7b947de561ac8104a0585f6136e13ba72de77a03a2cc1acce9e7e37b11897829fc8f010f1d5524f4d8390"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}