rule mysql323_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c481f213f3c4308"
    $a1="43e9a4ab75570f5b"
    $a2="5c1f1c181dedb604"
    $a3="35df6f8057f4142b"
    $a4="1f28e3d35c481b0f"
    $a5="61d0d847500347c8"
    $a6="5e15094634fac7df"
    $a7="38914f9560d4d960"
    $a8="32a05c464b1cc97a"
    $a9="4c5d7bda61187bf5"
    $a10="660b73791094ff88"
    $a11="660b73791094ff88"
    $a12="433b9dd07a62d629"
    $a13="660b73791094ff88"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}