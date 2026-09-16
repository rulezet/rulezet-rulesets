rule mysql41_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*BCDB46F9759BC3C7C2679D4E81145B53EE616059"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*516B09D2921A348B9E494C2D7AF4A7C8454C6FA0"
    $a3="*9F880DA1329B4B497F247AA25727CCDD5F4DD2E0"
    $a4="*1788A88203A94D7BF7C1682C51BBCF897DD17579"
    $a5="*8D6A637F37955DBFCE1229204DDBED1CE11E6F41"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}