rule sha3_512_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d7bc8ff047df30b118d405435e5c94bd038dbc77040b55a2fb2cdd2f2bb6f4656d2f6cd76c6d432e303264e65a0b802c9b21f15fbf254c3b2449a803ab0e490"
    $a1="c80072a6101b7360095ab0828fd92fb2e96d544ed09f855f32445c96709245d14687246cfc889d2446fd43ff4aaecd49f9b6ba23ef6060c65638b08a6fa28fc3"
condition:
    ($a0 and $a1)
}