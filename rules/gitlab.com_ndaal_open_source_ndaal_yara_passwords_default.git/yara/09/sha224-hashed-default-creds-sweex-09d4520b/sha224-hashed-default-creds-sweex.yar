rule sha224_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b12d3ac8ee3f493c393ac2283b41b878476773bf7ac110a7f851455e"
    $a1="89507e57477323f5d3a38b4ad4f5cb43e0713f827f9fafbb7aa59fe7"
    $a2="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="3febb630e97a4b8be0b40acbeb4edbd88a1483c57187f0493d7465ec"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
    $a7="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}