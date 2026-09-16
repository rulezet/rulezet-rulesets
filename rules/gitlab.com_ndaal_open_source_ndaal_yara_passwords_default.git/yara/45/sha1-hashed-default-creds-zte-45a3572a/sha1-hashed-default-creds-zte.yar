rule sha1_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9156e6f9e617cd4a8714af5f8f6b2a501fb6b11f"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="e8525661ec0e87cda05697e6e1f050a7ec6b2e8a"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="12dea96fec20593566ab75692c9949596833adc9"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
    $a6="9e88eb02399a8947cad2395b01595d848c7a1c87"
    $a7="844c590ba1ef3757d88ac4951bf269d17615c87a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}