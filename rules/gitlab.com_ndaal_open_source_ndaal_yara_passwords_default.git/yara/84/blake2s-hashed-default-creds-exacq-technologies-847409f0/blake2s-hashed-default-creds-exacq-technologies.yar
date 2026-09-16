rule blake2s_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eef4b0cfa00487c34423a31e7e5d0dc8a24e8efe9c7e722432960d0bf854d349"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="aeace455b133f4da1e59110fe1aad505d08b39e6f101a985d2c5846c16deb0d5"
    $a3="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}