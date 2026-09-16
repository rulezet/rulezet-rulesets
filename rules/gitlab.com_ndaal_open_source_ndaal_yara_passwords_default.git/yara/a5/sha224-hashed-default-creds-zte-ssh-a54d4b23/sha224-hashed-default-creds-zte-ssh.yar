rule sha224_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="38f8d57baab9a443fc59d111e3469db3177218e0ce7af1792109afdf"
    $a3="38f8d57baab9a443fc59d111e3469db3177218e0ce7af1792109afdf"
    $a4="4918203cd3497ed94eb51a7ad11b69c25cd192fd2442d9648cf0af33"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="0a6dfeb55d4efd16bbf4256c7514cc2c5e26ec3b83d425d74777ffc8"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a9="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a10="7b1d927b3f3fdf4b21df08279c2a2f3bb868acfa80d50f3cdef23243"
    $a11="7b1d927b3f3fdf4b21df08279c2a2f3bb868acfa80d50f3cdef23243"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}