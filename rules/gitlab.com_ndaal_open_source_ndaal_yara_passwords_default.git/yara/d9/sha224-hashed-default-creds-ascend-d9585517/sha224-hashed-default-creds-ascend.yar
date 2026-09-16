rule sha224_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329872e9ba9650413d00e126e516ec4e83233a487e455d4b44d59c28"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="aab31839eda6ae30c9e04b073a6c840b3da972c72ecd46f020c599f1"
    $a5="c3352c01875335502f888606000fee7f03bdf8331037cec22a1bb55a"
    $a6="931cb2c2657631363b8a216b6ae51002af953a5dac26fa43f60abca2"
    $a7="7525d4343f66352bf3e51528c809fd8473f7969996aa6b9fe9ab39aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}