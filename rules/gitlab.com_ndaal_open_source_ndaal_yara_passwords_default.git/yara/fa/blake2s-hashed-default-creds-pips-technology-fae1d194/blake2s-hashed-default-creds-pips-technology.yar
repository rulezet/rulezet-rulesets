rule blake2s_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fec74e6acbd030f34996103e61bb02459075b26bf5314c3664daca1ca829375"
    $a1="8fec74e6acbd030f34996103e61bb02459075b26bf5314c3664daca1ca829375"
    $a2="c71d04d1011f9bc585efc8a6a691c3dbe215327708a5ca0de4b8d4bc591da24b"
    $a3="c71d04d1011f9bc585efc8a6a691c3dbe215327708a5ca0de4b8d4bc591da24b"
    $a4="264861803adc0e9009b91730e72d831c5d150553952feee4c3cefcf1ff8fabbc"
    $a5="264861803adc0e9009b91730e72d831c5d150553952feee4c3cefcf1ff8fabbc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}