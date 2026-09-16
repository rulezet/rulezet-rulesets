rule sha3_512_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e30751de33626e6341e086cfa027a5347b36677acaa2325ff8d8b879f681bf41ce5c12b8564d4bd1478239ed5633ebffc7ebbcb1cd407ec585ff46c90788572"
    $a1="456152b8228074e349bf22781a0a8d924a1e69ae310e858069ae3bb1ca6def46dcb4df26878f786bd38da6fba4bef465e0496bf9471e6932ce13378d793174c2"
    $a2="0388d2b0d6427d3c7ba6a5c5f31b293ac90603bf73590971047f56733c52dcc7b1dc7b0bda35458ef6281a13b809223892fb1c94a70c657d09628514efb1d69c"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}