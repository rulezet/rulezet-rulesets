rule blake2b_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04134ddd131165ad52bcbe11800875556c75245a7dde83d127a2e83bba0fc9cd5097b1c04c743a75b224c28d9326471da47991869f2e05686e9c1da69eab192c"
    $a1="8da5525d49c047c516f2d19e05247aae07dc54e5d94ce1af5f4c099846113fca3f34950635d4d08aa057126009bcdd67a3a21a79186d4c7c5f50ea6738018aba"
    $a2="f1e49137c65993da285d960add379c5b1f63d9fbcee77026e3e191a5da7db10d5eedca3b4a5df348aa95bb75b5b914d3b0c3fdb10a3a9b99de8f118269c66ae0"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="b75c8c42a1c9216da01ffe3d1f1854706c5dc40a306a6bb76916e8bb93983d469542180373ca305ad5bbf8abc70bce61776f147eb2e041fd8e5367103d674e08"
    $a7="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a8="7465b053b832bcb98d162be89dbc054eb945b3e2ca42f99b2c20189b9e3dffaaf872a4b077d46026a4451305221fa6c94dc934d7a544f9295ce7bcc23aec31a8"
    $a9="5860893bfed0ceb5b3f4f874bc3e6256eabd1b3091f0cec26132ff8591b290a2647dcf236c153ac3895291cf2074dfa5ca1a5e0ea159cede8d84857cba17b5b5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}