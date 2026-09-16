rule sha3_512_hashed_default_creds_us_robotic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for us_robotic."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1fd0b56da32394c212a5aa993675d12eea0e0761d0662fa6ec068bd96830cd47cc914c0d8d12945f9fa346303aa91bbaf92d02874b27fd0369b36e6544e21c4c"
    $a1="1fd0b56da32394c212a5aa993675d12eea0e0761d0662fa6ec068bd96830cd47cc914c0d8d12945f9fa346303aa91bbaf92d02874b27fd0369b36e6544e21c4c"
condition:
    ($a0 and $a1)
}