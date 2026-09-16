rule sha3_512_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4e440f697e31b98cd6d02ae64080a53e460e5ec502bb61df8b1bdaa8f5ee4e21fc4c4a73f128298753b02cb9768d4a7622622e6a4157d9edfa608a6786932f4"
    $a1="a4e440f697e31b98cd6d02ae64080a53e460e5ec502bb61df8b1bdaa8f5ee4e21fc4c4a73f128298753b02cb9768d4a7622622e6a4157d9edfa608a6786932f4"
    $a2="bdb9e96e8b36ec882f4de8a77d2c023a4bd3df2ea0211533edd1ebca8b49c689c8a03c49f6f8f1e700d7c5b4038cecaf9c4ea296aec3584e5d064526edb002d8"
    $a3="bdb9e96e8b36ec882f4de8a77d2c023a4bd3df2ea0211533edd1ebca8b49c689c8a03c49f6f8f1e700d7c5b4038cecaf9c4ea296aec3584e5d064526edb002d8"
    $a4="57d4ab41183019c29a93b3b1dd6fe975070257eef551d95d081ff1e4749511bd4e93b21cca0a296a0ada5f457a500ac168db89edec3e13958f157518721a6772"
    $a5="57d4ab41183019c29a93b3b1dd6fe975070257eef551d95d081ff1e4749511bd4e93b21cca0a296a0ada5f457a500ac168db89edec3e13958f157518721a6772"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}