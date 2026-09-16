rule mysql41_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*D89A99106002D77C1D327FC41E005919505638B0"
    $a2="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a5="*BE0C64F8900D465CB1D23FE352CC2B0F4B7EC302"
    $a6="*B7273AB063A1055607237F2DD5A1A519F9362ABD"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*B207EF8923E9760F9773C62828F6451D3CCDA84A"
    $a9="*62BD1A28A2E76669460A4FD27F83937C76E907C4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}