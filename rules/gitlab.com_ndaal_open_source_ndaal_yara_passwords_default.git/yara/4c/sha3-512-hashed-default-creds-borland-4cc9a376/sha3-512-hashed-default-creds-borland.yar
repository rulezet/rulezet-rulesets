rule sha3_512_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77e64e949250e89a050152df260cbcdbb1cd22e506ca27554f7dd4e9dd96a1dc8d90dbe860789f2507ec403733ad8824038570efe2a445e59e6b9e2f0dcd8c2e"
    $a1="a14165b41dccd687eb18ed144307694bbc4e01af9693fc86dc0ab518a1292ae9180e063dbc78bd8a86e5054b4aea70ea2765215bdcdddbf9eaf688f78d664fe0"
    $a2="77e64e949250e89a050152df260cbcdbb1cd22e506ca27554f7dd4e9dd96a1dc8d90dbe860789f2507ec403733ad8824038570efe2a445e59e6b9e2f0dcd8c2e"
    $a3="7e3f9f76b6fad4c9905cdebaf93f24de322c172522f319ab011280f583ebaeccf2ddafb94db361519ef649a562e4d767f8c9701476f306428eae804fe526beb9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}