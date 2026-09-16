rule sha512_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4245998d35231f71d12f9dc299ffe2bc22ed3c1c3f59ff825bf6a27bc875169f0219c08c9e0560ae97e43a1baadeaaa9e82ba6adb451a6f1c62449c48a9024dc"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="50defc7946c9046a21b9d1087d4e8da7020df62b42efae6aeb7a20fd2593b190c6e3f26ba35dc0a9e9d7574bd95bc7364e42b2e4fa7d2d0dcd5f623e0e24beab"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a5="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a6="4fb0b502ff286c02473bdf07f55ec08eccab7a232ca1033f8d9b6a00c125788b13e5dfd0c26ad49191759496e8f0734d78b6111cf1cce87eea0c9c9fc1870d6b"
    $a7="8c608bb59aa76e6ad37bc1c9edfc62edb0a57b5fffd98e1a5e7358c0b245a30c910bbfbd1918a124cac7878e71fe7d469810d85fe92f93977b8f49aa58ff9f5f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}