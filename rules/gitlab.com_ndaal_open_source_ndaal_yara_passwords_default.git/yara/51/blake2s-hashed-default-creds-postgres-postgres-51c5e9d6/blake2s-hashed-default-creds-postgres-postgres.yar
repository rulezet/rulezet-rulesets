rule blake2s_hashed_default_creds_postgres_postgres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for postgres_postgres."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="0da254bc3667d03941a3095a2256300c4b25089720d4a324e02843c22fecdde4"
    $a5="0b417584c26fea0269072efa404634a30a93c1e929226917d229ca50dee85649"
    $a6="e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605"
    $a7="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a8="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a9="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a10="aedaed5061e8497b526a90c179783a3df87d23d7af08f01c0cd36763dfd7a759"
    $a11="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a12="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a13="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a14="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a15="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a16="90ad0f1fcf4f195caf6c4c7efb9230fbacc76a5cd94728cb60a81895f3608451"
    $a17="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a18="76fada65948ac2e8ff9a1ace9b082bbdf7c547b9a693865ae37ce29b624eeb98"
    $a19="17a18be2090aa98485a45d9f978f3a05fa3fc67fb05d253220d994089ebd1e7d"
    $a20="76fada65948ac2e8ff9a1ace9b082bbdf7c547b9a693865ae37ce29b624eeb98"
    $a21="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a22="06c72149011421e1f91fc6242d6c3b1a95cd9febaada1d3c79781beb2c8e035b"
    $a23="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}