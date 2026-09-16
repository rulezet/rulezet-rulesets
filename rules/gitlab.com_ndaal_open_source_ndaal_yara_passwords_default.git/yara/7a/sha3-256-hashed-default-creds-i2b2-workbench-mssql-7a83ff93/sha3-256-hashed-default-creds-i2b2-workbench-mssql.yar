rule sha3_256_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="564e5dc4a945c090099282aaec91c7008d1f633b77c54c604e24953d601e238f"
    $a1="dc503b4b1c77af67adb2826f965b679054a2b4a8a507ff6d3998768a3231110a"
    $a2="2f6fafe40e2c9b3cd901b7d33b147f50caab311a64015362096f8ac89dd994bb"
    $a3="ec1a98de88ea78eb5c7c5fcaac2fd46b297985464f027050092968a7127c356d"
    $a4="b1bc5f5e38a9a778917168082f4265f44ab63bef461301dcc24d59a3faa09a25"
    $a5="c49fe7fcc25d3b10755df66070a98c13b2383f3016a29c8e4eaa4cac4a164388"
    $a6="f94c407aae94e5241a332be5eb4ed728b567eb7314c49959d4144e47041d1200"
    $a7="2d960b67ed7ecced37067d9e0bf3b5921e5958c7c2ab72ae415602de3ef3a991"
    $a8="bc75743e1d99bf61fce1521c40bfba81e7aec87e9732ad59b617ce36e310631f"
    $a9="8816517c6234e6c58242ab0628732b4c18bf8ed5e6663305b032052d36c4738a"
    $a10="100d8c5b945b6ef9260c6654921846de4adafba13c27f3050d77e63c33dbdf11"
    $a11="03b7e32a3a6c800f30ef0316d54252a6cccb196652afd4c80e2713b6b0593802"
    $a12="b8b7fa3269ca681cb93722b14a61ab1ced46d6e3526e1607b9016f2d20fc7634"
    $a13="690583bff134ecba4fffb75f587cc536670dc33aa84626b6bb40dfede59c874c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}