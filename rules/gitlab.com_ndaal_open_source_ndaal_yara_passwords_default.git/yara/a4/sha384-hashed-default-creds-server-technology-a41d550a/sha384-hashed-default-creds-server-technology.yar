rule sha384_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e53a80692550f761f1dac51feb336dfbe973f089b2d5b3e34ca8284997c5de7cbc55d18b0334a9dbf5c80677138017a"
    $a1="21715b408927d6eef8de7f59241dbfd27c7c01e06f8153fe20aa2afd94623f641815cde23d887ad75b49ac5d4fd37729"
    $a2="67ac2ffcdd4ac70876a66b95ab887ff962b31f542b7ef0d35287109db31543906e13bdf8ddbcb37bfd61abb699410ad3"
    $a3="0fb5fdccdbfcdf43f33cfba26b36d6e691aa82ed6acad3583caf0297f3b4fcc15dab2663be2bbda5d68e11be6dab35f4"
    $a4="2912076b336ebdd783b83a95f3e114f736c8fbf6ebd8c091def825064c8dcce9d21f997858c49cb658891d7452b81c70"
    $a5="dea79ac15ec73e8eb1d0ced8c782bc37c63272287484286c993a2bc202ae8819c3284d2cad3324492a6c56b932d858ed"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}