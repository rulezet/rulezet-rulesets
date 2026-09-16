rule md5_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="746a296a2547b1a28ece1d9b45021f0d"
    $a1="82563c3301fbc3797ffd1702984f0a2c"
    $a2="290aa251e112152e01cb136466980fbe"
    $a3="384c2f56183aa57a44cc85be4f2e9b11"
    $a4="4281d43f721b976838f6c7d34a4094f4"
    $a5="33f8aadf7000eb8a5c63123c8b993342"
    $a6="72eec9aaa2014c22df5337ed180030c7"
    $a7="75c9e6efa323340cbcb2756a08c40f23"
    $a8="c1673d10dd6922e92f2fce940676b88f"
    $a9="d7d4724929ab5922dcf562fcf2723110"
    $a10="6b87bb6786cee7e0ae0036f068270442"
    $a11="c99776caa9ad70bbd1fd9d79052c3529"
    $a12="7b5679d2070b773b13f8e68d205670af"
    $a13="9889fd39c16285ffa66a69eb9d524f06"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}