rule mysql41_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*FCEAA1CB0EDDE29E10614EA822DB0CB0A943FAA4"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*FCEAA1CB0EDDE29E10614EA822DB0CB0A943FAA4"
    $a3="*F5AB3475E4D0309381498567B7C7A270ADED2652"
    $a4="*9E351BAC81422C58648B8D1AE37F369E57A7DAFB"
    $a5="*BA029B8A98C6835A5523F4995B2EA34D1EB9954A"
    $a6="*9E351BAC81422C58648B8D1AE37F369E57A7DAFB"
    $a7="*9265F6647EDA8FA891BEBE9F103B9CB6B43DA03B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}