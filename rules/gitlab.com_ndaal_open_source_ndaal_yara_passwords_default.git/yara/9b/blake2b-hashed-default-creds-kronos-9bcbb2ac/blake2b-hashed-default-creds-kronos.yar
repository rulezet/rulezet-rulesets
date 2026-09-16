rule blake2b_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b3a06fd0438a5c4b00162998f1bb66f08d45cce1eaca416389ed1a497c0e9beeb241e2717edcc3caed6a902bd02af7a42de79da9a8c548dff5396c8e22da8d8"
    $a1="68b6cc0a781688a06e4a65e73065ed47a10ade4977c747140ca08f8e08d27d4a2933f91cad80683008a6854c1907ac5af3f75c3755201e03d4eb6c89cfc8261e"
condition:
    ($a0 and $a1)
}