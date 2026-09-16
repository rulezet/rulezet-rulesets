rule blake2s_hashed_default_creds_lindsay_electronics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lindsay_electronics."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
    $a1="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a2="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
    $a3="dbc6fce231000dd41ea6062469fabf61d11d0f9a266f89c432c17aac25e921ce"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}