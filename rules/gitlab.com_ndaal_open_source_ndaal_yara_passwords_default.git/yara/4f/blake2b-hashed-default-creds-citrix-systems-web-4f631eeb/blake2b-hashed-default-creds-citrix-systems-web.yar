rule blake2b_hashed_default_creds_citrix_systems_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a1="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a2="d651a36187b6d01a9812213aa56682d60e1895af80b9f596d1e7167139a4c66564a1fd35fa236312ab6a961353456e6953b3409da643b384192b3156e75ee37a"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}