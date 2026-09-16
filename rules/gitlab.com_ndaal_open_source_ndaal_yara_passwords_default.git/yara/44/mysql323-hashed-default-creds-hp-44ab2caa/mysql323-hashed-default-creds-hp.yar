rule mysql323_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5d2e19393cc5ef67"
    $a1="67457e226a1a15bd"
    $a2="1416b82b47841842"
    $a3="59609e62287da4e7"
    $a4="1f6fda9414d32602"
    $a5="70072ea81fbd7474"
    $a6="07ad1420274d966c"
    $a7="70072ea81fbd7474"
    $a8="700cd614639f89fb"
    $a9="43e9a4ab75570f5b"
    $a10="5e2b7cd912a2d912"
    $a11="58573d166f8f9ddf"
    $a12="43e9a4ab75570f5b"
    $a13="58f7ee435f925abe"
    $a14="43e9a4ab75570f5b"
    $a15="43e9a4ab75570f5b"
    $a16="2a401d943e6d083d"
    $a17="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}