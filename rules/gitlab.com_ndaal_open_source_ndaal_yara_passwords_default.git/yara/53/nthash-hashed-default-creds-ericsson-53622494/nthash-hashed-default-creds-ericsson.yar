rule nthash_hashed_default_creds_ericsson
{
    meta:
        id = "6NUaDlYwStwUx1U98sfwDi"
        fingerprint = "ea6f4092e79af0ab541f93d453c5d54f386fe1afeddd007e6d37eb0469d96602"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="198d23ce47e7ab51349d595a24e451bb"
    $a1="198d23ce47e7ab51349d595a24e451bb"
    $a2="7d891ab402caf2e89ccdd33ed54333ac"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="0333c27eb4b9401d91fef02a9f74840e"
    $a5="1004f9d3cac7359299a976fd0fcef99c"
    $a6="5655c692e5c9b6ca60eb7d953cf8a921"
    $a7="5655c692e5c9b6ca60eb7d953cf8a921"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}