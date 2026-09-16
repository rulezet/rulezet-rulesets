rule sha224_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a1="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a2="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a3="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a4="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a5="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a6="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
    $a7="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}