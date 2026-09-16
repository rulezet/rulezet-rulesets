rule sha3_384_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a02addf854b2f81b447883ab29038c6458fcd0e6a191360584ee8708f55c4598932177e6427004dd0272cfacce17094"
    $a1="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a2="9bd942d1678a25d029b114306f5e1dae49fe8abeeacd03cfab0f156aa2e363c988b1c12803d4a8c9ba38fdc873e5f007"
    $a3="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}