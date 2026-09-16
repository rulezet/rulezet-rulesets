rule mysql41_hashed_default_creds_ibm_storwize_v7000_unified_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_storwize_v7000_unified_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*830A96CC094C26FC591231B3C9DBEFEF8DB09EEB"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*DDFB542AA0BD1D251995D81AEBEB96DEEAD1132F"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*74B1C21ACE0C2D6B0678A5E503D2A60E8F9651A3"
    $a5="*F5AB3475E4D0309381498567B7C7A270ADED2652"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}