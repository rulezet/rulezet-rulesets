rule sha384_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ce9a273f635c5e5a87de22eba5e797683d1e07b414fcf42e0e9d0e2cfe3378769f712bdc446d95c32b181c092aaef20"
    $a1="5f7c68c0b49811ae6114ab6ba14e2464d37918365fdfef4414fab738cc824bfbb09c085c688e4984972656215fc23965"
condition:
    ($a0 and $a1)
}