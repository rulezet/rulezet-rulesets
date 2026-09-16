rule sha512_hashed_default_creds_modernie_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for modernie_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fb34f7b753a936ea0ffd9d569918241809b4f187b00121ad63518f432d46835bb40e2bd3681865b6630a32a753e8534793aa3c96376b1101e0700e1de79534e"
    $a1="793eb58a2fdf9f8de72659580f8414f841dbae459d0d60230b9ca0f18f2c3b591d887e07055f9fef891909bd155c26d2ae39f76e886f87523a5a8132840a9b3d"
condition:
    ($a0 and $a1)
}