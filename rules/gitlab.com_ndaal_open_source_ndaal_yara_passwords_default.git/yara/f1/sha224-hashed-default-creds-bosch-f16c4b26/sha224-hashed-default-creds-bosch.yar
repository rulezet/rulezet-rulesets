rule sha224_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a1="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a2="834633ea2115ea629e018e15fb0c66803598397085b80d10d5b95f1f"
    $a3="834633ea2115ea629e018e15fb0c66803598397085b80d10d5b95f1f"
    $a4="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a5="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}