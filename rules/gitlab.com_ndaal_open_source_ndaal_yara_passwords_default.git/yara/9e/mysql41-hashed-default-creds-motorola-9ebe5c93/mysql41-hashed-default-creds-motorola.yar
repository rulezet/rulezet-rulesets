rule mysql41_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*63DA4EA8D1848C115BC12C4956B7ED85510A216B"
    $a1="*6EBBEE79F2314B26A7D8BA22E2B652D43A997EB0"
    $a2="*0F6DB8D764AB9D89DBB30DAA5B682B889569D4BC"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*B4FB95D86DCFC3F33A3852714DC742C77504479D"
    $a7="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a8="*C426DB257270F4338CFEC8DDD210CB33C738FDDE"
    $a9="*89454C1CCBF535F73F185D2994A97B8F83A63EAC"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}