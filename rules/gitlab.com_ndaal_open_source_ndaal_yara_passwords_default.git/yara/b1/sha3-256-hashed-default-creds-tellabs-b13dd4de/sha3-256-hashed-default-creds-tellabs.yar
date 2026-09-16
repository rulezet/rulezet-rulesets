rule sha3_256_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0616fc6541f2b8164099fb077d17ef9eeb5cd92872898298942db8acbcee0600"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="61fc5eb531971522373c05fbb7d50ef2fd5eed08b841135e78fbdc2cd19a5927"
    $a3="531c19f116fd82c8d06fe23171e1db63a0a252224337ec26b3fcdd39394783c6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}