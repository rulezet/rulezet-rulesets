rule sha224_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a1="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a2="f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="84afc65caef3282b304e5e1a84108c455b36ef32ec4b06f11b9c0d3e"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="b071206b92c208e609fa3eb492165c271b41ad94cc0134bffeebf766"
    $a7="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}