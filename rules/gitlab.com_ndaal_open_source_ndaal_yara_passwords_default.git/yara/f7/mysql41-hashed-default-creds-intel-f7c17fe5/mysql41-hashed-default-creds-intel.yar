rule mysql41_hashed_default_creds_intel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intel."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a1="*18ED90460331B8E9FC796D9FF923A720D3EF8592"
    $a2="*64A2D91B7CD940EFDEBD95314E10E165FC97CFFA"
    $a3="*64A2D91B7CD940EFDEBD95314E10E165FC97CFFA"
    $a4="*D361459A995F83C86EA7AD92FB445BDC09E18AC6"
    $a5="*D361459A995F83C86EA7AD92FB445BDC09E18AC6"
    $a6="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*868BAED7EAE3307F093BA0D88BE017C1A457EB19"
    $a9="*71A423EE610B82E6695F355B08DD252520BF3E0A"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}