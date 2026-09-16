rule sha3_384_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53d93821daa5cf6912fc22216118b625b0261cbfa4666d5847d42b99664137aacd4e31e3ea4a4d0df2a1695c2c1fabce"
    $a1="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
    $a2="9b5a4bca0c036e9cb3ac5a2bb3c9bda4e892a2a66bdca42f60459e6d6e01497cdacdf09b4a7f05d2b5169dfa7b98a06f"
    $a3="f4b956aaf8da19793edd03baf5de66672461717259212e03d599290bead33bd556c9c6fc193277a8bf0ca7c5bc3cddbe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}