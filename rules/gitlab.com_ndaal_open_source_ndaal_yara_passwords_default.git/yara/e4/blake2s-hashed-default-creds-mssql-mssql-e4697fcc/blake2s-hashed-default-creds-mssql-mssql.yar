rule blake2s_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d59a7cc6209c3f94370d665a9dda648e474e83a83ba9a35d3b1bc55aaf69747"
    $a1="ab97aaf4444dff189620a33572991c8cd0ab8294466d624b4ed610beb13f2aac"
    $a2="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a4="e80220afa6bd68f7176903c33deb49f3d32ff3cd91668af087910fcb73180c0c"
    $a5="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a6="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a7="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a8="8a7a4fdc3c3e51dda63342b46acf87f375869c268a61715ffc5331e11f46dfa0"
    $a9="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}