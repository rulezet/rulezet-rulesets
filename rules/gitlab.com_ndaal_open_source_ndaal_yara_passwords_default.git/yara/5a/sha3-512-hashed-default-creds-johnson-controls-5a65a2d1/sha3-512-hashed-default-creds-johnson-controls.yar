rule sha3_512_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2137bfab95ff98094e876560af3f171f06c4aac4473943764babf91f7797b37a269e36867c1b9116f9f7c01a0d8f91fd1df82b6093ef827341e1c24217f95fab"
    $a1="69b0409c73653ae5f6fcfad7c83e978afb19749488a9333a2c42a90ebe80d823db1d2c9f73c5b37517257b9263d9d3e068f818e18a56379066b1db0a04eb2d32"
condition:
    ($a0 and $a1)
}