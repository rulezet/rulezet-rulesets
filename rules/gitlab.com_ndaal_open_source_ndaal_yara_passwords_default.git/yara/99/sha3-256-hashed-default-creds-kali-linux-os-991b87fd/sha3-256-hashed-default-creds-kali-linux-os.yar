rule sha3_256_hashed_default_creds_kali_linux_os
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kali_linux_os."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aeffb032a51d224814e7c8d876ec433aae4ad44cd6362dc26b6b9cb750c7620"
    $a1="3aeffb032a51d224814e7c8d876ec433aae4ad44cd6362dc26b6b9cb750c7620"
    $a2="e5ead65714a14368b08263779941b023f2d991e97fc7e888752616f5da2fded6"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}