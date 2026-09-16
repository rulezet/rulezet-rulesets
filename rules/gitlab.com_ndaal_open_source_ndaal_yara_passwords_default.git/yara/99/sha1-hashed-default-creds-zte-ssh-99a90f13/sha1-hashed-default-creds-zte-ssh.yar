rule sha1_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="db3d405b10675998c030223177d42e71b4e7a312"
    $a3="db3d405b10675998c030223177d42e71b4e7a312"
    $a4="c3c9ce19dc5c0fd853c30bc8252611d3981ff9c6"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="8df2ae0668218b74822da6e7de4d18b678230bd6"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="12dea96fec20593566ab75692c9949596833adc9"
    $a9="12dea96fec20593566ab75692c9949596833adc9"
    $a10="d38d6f003b9f1ce8190a3ab3a4fb234ad811107f"
    $a11="d38d6f003b9f1ce8190a3ab3a4fb234ad811107f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}