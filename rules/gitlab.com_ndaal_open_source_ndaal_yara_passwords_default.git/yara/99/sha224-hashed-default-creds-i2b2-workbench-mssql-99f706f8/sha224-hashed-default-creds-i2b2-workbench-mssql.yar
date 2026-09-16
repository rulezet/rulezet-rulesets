rule sha224_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="33476bb0e45b3b78bf6ee2c7ee202050a045269ebecf80aea27a7c04"
    $a1="80761b7d060a9ea0bba1bea618d67aca65a1af591c52dae0b2c8848f"
    $a2="1367f0b33a863292cf921557e15676e49a9bae6cc0dbdebeed9a219e"
    $a3="978858a3ac2b429d66169645c7c284ca50e9c8d2a9800d99246f3d99"
    $a4="391572c0204fddbc68e91f0e808f07d4b7e85b341966fda81ec1c831"
    $a5="f2fd55fc6becff8b352f852235e970896129d1e016331853d1bf6fd9"
    $a6="b367f8059dc59b4d7d54690a47c1622a703db697dac3759a59fa77c5"
    $a7="6a6f517834010ffd590e765b6692f429f3b92ec8a7c3a125fd168866"
    $a8="c4b4ea2a350d33bfffb202196e405aaad052274d1da74b3f624cc2c3"
    $a9="19f570b0d360fd05abeb1995770514e378acfc95e43ecd82a4252895"
    $a10="e347e2526a09c43c2385957c095398a9d9dea63691ed9772390d4a07"
    $a11="d8b657ff5a9c6445187c3b6275ea898d1eb3ade5da78b6ef45047ba5"
    $a12="ecce30ce23e92c71a4268cace9de4cecc564b5b462225242492125e9"
    $a13="fcb385f11a378012e72caf864aa4a7deda3f76f24fb4fa72f10afbe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}