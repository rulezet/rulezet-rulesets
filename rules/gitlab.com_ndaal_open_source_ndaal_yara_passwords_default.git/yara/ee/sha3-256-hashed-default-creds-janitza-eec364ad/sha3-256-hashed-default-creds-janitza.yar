rule sha3_256_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
    $a3="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a4="78e8502f74b4be418b11228346f8fd12b60be9846cb04734faaa0c95433d70a3"
    $a5="c83d1a8c35171808c4864d063d67975dca903349acfea45a1d995b7c588a80d6"
    $a6="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
    $a7="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}