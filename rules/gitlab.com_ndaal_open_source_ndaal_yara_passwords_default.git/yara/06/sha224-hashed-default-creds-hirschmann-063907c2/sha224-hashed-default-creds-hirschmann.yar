rule sha224_hashed_default_creds_hirschmann
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hirschmann."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="888fad770c3a27c39b480fff6350198462b46ff1d4bd01a6ee7dc24e"
    $a1="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a2="2a12e8d906468d24de4552c04fac544c36a2775d6a4d206bbf20bb43"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}