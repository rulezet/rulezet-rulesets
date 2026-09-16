rule blake2b_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e3aa1a799fce5de0e40487976697086347277090db2c17e2828b8620b4137b0c2a4c837ce5d6099b33a06fa3c775917a20fbeb9c3ec2c33f23479e3435fd2bb"
    $a1="3e3aa1a799fce5de0e40487976697086347277090db2c17e2828b8620b4137b0c2a4c837ce5d6099b33a06fa3c775917a20fbeb9c3ec2c33f23479e3435fd2bb"
    $a2="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
    $a3="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}