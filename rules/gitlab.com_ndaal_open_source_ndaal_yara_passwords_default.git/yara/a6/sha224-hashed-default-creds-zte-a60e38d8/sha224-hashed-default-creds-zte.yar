rule sha224_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d8e47ec9eff6e80c36099e742808d802dd561a7561cd35218b874ec"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="144395f4c37bfe49b683aa17874aa9bd00e026ba174b92d514df3f07"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a5="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a6="037921f105c0ad458943f805364d257f4daae2498a302d3437a96bd7"
    $a7="289c88d937d35f3669c94e2ad1fc9f56d0af0267683e85f00d281dec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}