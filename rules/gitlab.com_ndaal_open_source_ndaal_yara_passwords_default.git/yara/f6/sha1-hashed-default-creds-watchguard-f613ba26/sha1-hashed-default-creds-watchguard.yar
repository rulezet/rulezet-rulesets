rule sha1_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9d4e1e23bd5b727046a9e3b4b7db57bd8d6ee684"
    $a1="12dea96fec20593566ab75692c9949596833adc9"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="accf881e821ed62ca842d34164426a7d9215a948"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="9a27718297218c3757c365d357d13f49d0fa3065"
    $a7="48a3661d846478fa991a825ebd10b78671444b5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}