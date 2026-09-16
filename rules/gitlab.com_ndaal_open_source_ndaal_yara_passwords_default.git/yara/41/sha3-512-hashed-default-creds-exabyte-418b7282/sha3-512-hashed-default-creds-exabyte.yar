rule sha3_512_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80464c1b965da52c1b52b88e09173047740675facdb620b5fef95413b1412e76fc2e83a9a4c7c8e54d98ff513bae4acc0c32bcb16be429b701446373751bbf35"
    $a1="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
condition:
    ($a0 and $a1)
}