rule sha3_512_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a1="e31c51bdd66677ebe710ebb5c0f216d4a8a8210c501ac97fe54beb1b93bac89c9d40ae2da98ccf94c81881721c0d09999ee2d4c0afcb5c5bbbc6e77506f48d10"
    $a2="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
    $a3="dfbd646332d1b53596068288f6b284fcced07fef20395cc50dcc1461c1e47c76dad59955048267edadc353656298508a4b8f48cac28ca2049368141f38c4a7f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}