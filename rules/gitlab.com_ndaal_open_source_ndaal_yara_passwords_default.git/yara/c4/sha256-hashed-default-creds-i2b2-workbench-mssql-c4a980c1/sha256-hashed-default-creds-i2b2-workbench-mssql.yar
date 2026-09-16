rule sha256_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d27c6a8865fc93b7cdd8a0b63d7b8ededbec82bd52450dea256b94650834876"
    $a1="12f31efb95145165dd1716a887e99b851bb8b4e4b2ca31f78bd7654b3d61ac6e"
    $a2="16773b7fc085b0e55ae98e02e053cb325217f1aaf83d63c9e646a67344a9ecaa"
    $a3="57183307c7337fb45996bc1fcd633beafe55781a5bbba1b95bd1b5783d0167f9"
    $a4="69f2ee9f38421d43d8bb663bb183b7b1b438db88cbde697441b77cf0367179f9"
    $a5="973a801aec5abfb0dd9ab3f429be4b7a7894d23362d049ff63a2687b0a00194d"
    $a6="f03f0760bab3dab7536f951d419198fae0397f704882110d1405c8565922d659"
    $a7="965c060d0cbd81ed7b673980c46bcb4e01e42354ed6d64ee7354f732099c88be"
    $a8="55ea7d11cabf3c16654164646337c1ee61ad792d20f00ee726c95fdaf2b95040"
    $a9="d6a5a0d16e0fcc10849438cd2475300662b916c18bfd8777bf63f05861de9ff2"
    $a10="3898ae9dcde0e53faf12cbbbf64799ddad7630000e054af1a32debf907b33066"
    $a11="542e2cdc8c4bb1e815215e587f3f370fad637a6f7cf560f5c825a4640f7612f6"
    $a12="75d2f413abb842c64f8d8fa31d78593afc64bf3a75caa5e1db41d082b92f98b6"
    $a13="e3e990bc053688f87de9142738aa9150699805e9637632f0bf9da462d5136a1e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}