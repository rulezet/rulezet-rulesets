rule sha256_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a1="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a2="799824ba3560d3955f302c392de50e2232991ffaeca6f24200cf46571b523489"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}