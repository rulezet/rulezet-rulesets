rule sha224_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7e0bb6ef7aaf18827ae1795e0e0c4a1ad04f757e52f7be4d1a64a309"
    $a1="08c8e4bd5c31533ef86dd65712b2270cdb6bdd4b355ff2e256be618a"
    $a2="974919085ef3eb519735f922ebe848a39cb232e16753d7beea28a7f4"
    $a3="2bb6da4701038c5586ad48ea2ce0310c9c0db13003fe7f3feed8e179"
    $a4="2116ce8cc0edb956788533a040f4674e505eb2b36213a8eaaf6d48c2"
    $a5="d56de952c2b48bb50abadcc10cbacddce31a977b93450ff57dbde5ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}