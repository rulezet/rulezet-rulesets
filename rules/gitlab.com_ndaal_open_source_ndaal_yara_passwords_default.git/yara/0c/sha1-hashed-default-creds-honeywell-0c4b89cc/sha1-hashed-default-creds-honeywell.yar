rule sha1_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a1="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a2="90e733e3382e15d3136316b614caffe5ebd6442a"
    $a3="c26ed5e2918203184fc35d4fabab0a3841fc011a"
    $a4="d83a104ca192932466cc1e308b49757ba8ce39f0"
    $a5="c63b77b4619ae8716d3f0a99e17383c2ad8e7282"
    $a6="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a7="face83ee3014bdc8f98203cc94e2e89222452e90"
    $a8="9d75342c103a050cfb09b05960bb95d6dc1335b6"
    $a9="bdb83fc840d550d2e7b07d550c22c712fa028a27"
    $a10="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}