rule mysql323_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="5d2e19393cc5ef67"
    $a3="43e9a4ab75570f5b"
    $a4="728889ee26187486"
    $a5="3674ddf769d8ef47"
    $a6="773359240eb9a1d9"
    $a7="59687415734be622"
    $a8="43e9a4ab75570f5b"
    $a9="59687415734be622"
    $a10="35f0bfa1126731ec"
    $a11="59687415734be622"
    $a12="5d2e19393cc5ef67"
    $a13="59687415734be622"
    $a14="59687415734be622"
    $a15="59687415734be622"
    $a16="5d2e19393cc5ef67"
    $a17="59687415734be622"
    $a18="43e9a4ab75570f5b"
    $a19="59687415734be622"
    $a20="43e9a4ab75570f5b"
    $a21="43e9a4ab75570f5b"
    $a22="5d2e19393cc5ef67"
    $a23="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}