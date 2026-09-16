rule nthash_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        id = "3WJPacqUoKQp9377ILYoH6"
        fingerprint = "98b37e29ce178392dd0493c3a0d6e09fd3e002629b6bb69747afbcdb8d913bc3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="573a649fd2f8234a631ea0e23bfa71b9"
    $a1="b809b5815d39c174486c2fb6f84ac649"
    $a2="466ac283d62ba57192638c5c9b9ea81f"
    $a3="2637d9580f1f862a7b352dd8680f33d5"
    $a4="54307eec272cb1e3729380afb7f8d68d"
    $a5="9173d233e451f1d18c52c9508f0758c7"
    $a6="93945276ac41d92d1e7faae4a42dc115"
    $a7="aba95e66a492a8b214b1ba241392a0b8"
    $a8="d3fd0345f4191ee91fd34e70bd193607"
    $a9="01d4e1240b76f6685db074a8172fac90"
    $a10="9bbd0ffa7050cef0ea2775263d8daa2e"
    $a11="47373aade8c5268530100d1f431fb380"
    $a12="a29d375320fa58650031dbbcc5004112"
    $a13="15cb92c62fdaab54f087b90fbebcea72"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}