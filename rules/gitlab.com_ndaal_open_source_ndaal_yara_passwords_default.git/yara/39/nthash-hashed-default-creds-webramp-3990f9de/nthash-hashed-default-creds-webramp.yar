rule nthash_hashed_default_creds_webramp
{
    meta:
        id = "7JUq1TaGeliFzsAMVFuyx8"
        fingerprint = "89c3990036b359ccff95ae652c6aebdc615d25fcad947bbf7d052651d8cd0020"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a255b8b631bfe904080f7f0791ae87bb"
    $a1="e8e7289454393110d7d4bc415fd463f4"
    $a2="5ccf0e02493b091bd69dafa58f082a35"
    $a3="e8e7289454393110d7d4bc415fd463f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}