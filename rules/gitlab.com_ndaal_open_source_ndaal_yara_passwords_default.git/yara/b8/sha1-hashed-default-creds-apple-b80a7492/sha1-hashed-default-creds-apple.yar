rule sha1_hashed_default_creds_apple
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apple."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d34076fc15db1b7c7a0943045699eba6f186ec1"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="5d860037008517edc1b3aa25911dd9e0cdfd731c"
    $a5="83d6311e87d4775ca4b3a411e3a334581ad8951e"
    $a6="61c9b2b17db77a27841bbeeabff923448b0f6388"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}