rule sha3_512_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
    $a1="24233f2a810a5f885f30dca512fa21e54407dd6adee36938324d6d46d8d6b44b052f7b325d31e4f64014ad0be37854c52f9f026c27f20405231c088e1edbde69"
    $a2="7ebf2ec2873c61214592fda44f3b6d2117867a908545d19677179219aed9251622b222ca60e3555d2685ede7e8227affd37404dffa5f54acdb269387ded70896"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}