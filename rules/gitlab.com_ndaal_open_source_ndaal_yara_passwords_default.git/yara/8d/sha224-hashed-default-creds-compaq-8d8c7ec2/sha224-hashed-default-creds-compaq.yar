rule sha224_hashed_default_creds_compaq
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for compaq."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="3a08a5240f31d0f9a4a2056d646b5edd302a9f9c065b46d050439704"
    $a3="b7f6b6eb03cef26c29b6c2a0add911bc2693226aa15a86b6db810080"
    $a4="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a5="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a6="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a7="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a8="888fad770c3a27c39b480fff6350198462b46ff1d4bd01a6ee7dc24e"
    $a9="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a10="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a11="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a12="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="0af5f61619a226b4a59dbab983fb0027d12dbe9fb438e89835539982"
    $a15="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}