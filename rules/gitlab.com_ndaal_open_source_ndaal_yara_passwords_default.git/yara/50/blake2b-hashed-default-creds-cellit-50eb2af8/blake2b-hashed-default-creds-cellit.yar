rule blake2b_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8de8daad1e9de94269e6e15cdbdef413c65c1780e19d77645782bb43e99dc6a2d68fc2dfadae12b45f11e19c191d5b2ba59f4275fa044016ff5e77ad842818b4"
    $a1="8de8daad1e9de94269e6e15cdbdef413c65c1780e19d77645782bb43e99dc6a2d68fc2dfadae12b45f11e19c191d5b2ba59f4275fa044016ff5e77ad842818b4"
condition:
    ($a0 and $a1)
}