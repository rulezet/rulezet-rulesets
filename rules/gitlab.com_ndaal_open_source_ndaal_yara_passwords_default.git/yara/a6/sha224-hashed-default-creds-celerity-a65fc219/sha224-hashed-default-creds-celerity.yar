rule sha224_hashed_default_creds_celerity
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for celerity."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee8ada0d3f4ec7b03c06ea18d778520c7ba9604e0b116fb4badebbeb"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="2b083a6f86773daca4b5272441195a178a8e6e25e7e73a3b9e4b2eba"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a5="db91cc04dd0f28d4449ff9c475ef0a8d0b129f414f0653ddef42c04e"
    $a6="a66fe10d2ccf30b0e04081ce304db4670cc631d7ddf3ca5c41848b43"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}