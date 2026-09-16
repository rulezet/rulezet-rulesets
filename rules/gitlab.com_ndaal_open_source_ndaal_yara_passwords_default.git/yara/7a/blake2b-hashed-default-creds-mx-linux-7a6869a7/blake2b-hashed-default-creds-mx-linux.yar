rule blake2b_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a1="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="56ceed7e63a70e54961e635f5d50915b522cfc98c2a21dc61a9548fbe7f5eb139d66d1bda40ff1033abfc796e53bf2dfa56aa00429d130ade11e268db3b3e08f"
    $a5="6ac142436fd99dcb9a7b944f295af7ba5026f6e8baab6d149820a4b9802b5939c97d0aad3083eb62cebb2983aafb98c743aa3390dc0d23d0a4719ae0b96d2f01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}