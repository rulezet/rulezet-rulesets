rule blake2b_hashed_default_creds_pokertracker_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pokertracker_software."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d441e702fb07b873451c77529f9f335a2ab25b366bb9506abdbc4aad763bc1d386a35461dd9f052ce32fd24900f44e70967190534a9fc92808f8d4e696200e55"
    $a1="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
    $a2="b90adabbaf359ff867a8244f8578e42208b1b31adc4fa3467a97d1fa0182690c66863568f360887183beafa242f15de0dcf092b9210ea2bd459e015e666b7ac1"
    $a3="cdef67c910369c447978f796ae4053b88d6e00d0b86c734550c8e35413ddbc6abd55237a04b4dbc13866a800d2079815448457e5d241f11d34aaa6853b636230"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}