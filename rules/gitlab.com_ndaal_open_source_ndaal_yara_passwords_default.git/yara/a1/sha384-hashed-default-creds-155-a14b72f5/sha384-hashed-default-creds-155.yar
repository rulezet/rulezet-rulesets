rule sha384_hashed_default_creds_155
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 155."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da5d66dd3bd1dcae077c06bc64b7f3315a6f13b21ac0921081b9e97d95fb5203057015b95f98368cbffa3400ed8900ad"
    $a1="b345909bba936cdc8ea81ae3ffe6c668481d351df7c46efd502f7f7f94dff566d40a9ecaa6621609419ad1903f74a799"
    $a2="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
    $a3="d7d4375a6045ae4b2dd32d6ccf53ee632c2d858cc5e67b2292f60e7e497f3f22efa1093e67ff66301ef64633437df096"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}