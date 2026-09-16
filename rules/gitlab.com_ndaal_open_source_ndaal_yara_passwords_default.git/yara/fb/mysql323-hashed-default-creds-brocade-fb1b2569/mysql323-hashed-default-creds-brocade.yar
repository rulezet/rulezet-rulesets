rule mysql323_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="451175250abf67b5"
    $a1="09764ab6574b6a9f"
    $a2="7ee389d765cc054a"
    $a3="67457e226a1a15bd"
    $a4="5d2e19393cc5ef67"
    $a5="43e9a4ab75570f5b"
    $a6="5d2e19393cc5ef67"
    $a7="1a486e7929011a28"
    $a8="0926ceb30c947ba4"
    $a9="67457e226a1a15bd"
    $a10="52280c3b462319d3"
    $a11="43e9a4ab75570f5b"
    $a12="23295a4734722244"
    $a13="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}