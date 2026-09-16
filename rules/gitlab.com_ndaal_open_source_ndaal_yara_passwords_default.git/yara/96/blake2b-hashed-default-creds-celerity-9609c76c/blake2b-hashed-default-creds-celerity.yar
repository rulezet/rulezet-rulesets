rule blake2b_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a5ddc62aa7be4d13ebf92fbb613db776b76bf4fb822a855792662dc983cb07e5dabbd0c471976fe1424ec3c2a81a400589e76795e6226e06c7cfec5d86363b42"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="7c9f6370dc07f5ed1ed3365459726c975ffac72cc69bf35397049b93d228a7e52810306b4cd8ae6b580f8254f3807fcb9d0339ac366b7877cb32c72eb774c0b5"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a5="4d5e70857236af965ee93b8e260157c93e30d29252ded4e689507991566b49056115715af73ec6e8094e78d6bfce5d0f76879c47d969ae20196107c0ffec0bf2"
    $a6="94c543f416cd2b4b9c06c31a745b5b578f0b71317cc20d6b18abbad48ff5e664bde6e71e89bf68d22bcc84578b9867abb549d1b3e51b1633ab3b922e3e5800d4"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}