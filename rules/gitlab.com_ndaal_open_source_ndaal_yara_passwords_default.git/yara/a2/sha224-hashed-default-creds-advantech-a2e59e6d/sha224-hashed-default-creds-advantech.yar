rule sha224_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="d777fced94de701abc5e2005f187297700e232ce2d5e3f9093856488"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a7="863d4fea750b9c44504c7a774a6c13a95a4e24675a006b58b78fef9e"
    $a8="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a9="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a10="3876dd6e14a7097c1c732a8777c26757b5eceb87111cac26a1f4f5c4"
    $a11="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}