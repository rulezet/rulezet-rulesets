rule sha224_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="eccdf0adddfa793166dba90f4ee2d7353a327b397686680fbb9bdb61"
    $a2="bca7995d44efc605a108646208bdc492e38f10823600e9427619621d"
    $a3="eccdf0adddfa793166dba90f4ee2d7353a327b397686680fbb9bdb61"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}