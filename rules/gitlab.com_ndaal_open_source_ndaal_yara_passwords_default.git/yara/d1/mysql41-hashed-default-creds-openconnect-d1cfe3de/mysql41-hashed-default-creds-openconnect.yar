rule mysql41_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*99A00E899E3A439453D81E2210FC3CD7414C6140"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*99A00E899E3A439453D81E2210FC3CD7414C6140"
    $a3="*D31816E12D77D25C33AF682454BB57B91D04EA66"
    $a4="*99A00E899E3A439453D81E2210FC3CD7414C6140"
    $a5="*2885FF2B3FEB66C3AF1F0411561567CBAC7A92DC"
    $a6="*99A00E899E3A439453D81E2210FC3CD7414C6140"
    $a7="*7BBC859664EF8EBCEEA2FC706D9AF1B70BBB6913"
    $a8="*99A00E899E3A439453D81E2210FC3CD7414C6140"
    $a9="*20FD0A197938E46F83AD4F5216E1F5C11CD03A52"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}