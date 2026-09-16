rule blake2s_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a1="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a2="14b93338406b7166cefd29f6622e20e388c357ba6fc782e5f0b8f46977dd1b6c"
    $a3="83a62c3efce84e77ebcc76ae4132840d21e4fc28bc07a43ff9a67ab5bb58be4f"
    $a4="be5bd5bf4ad1e62310b143736e8fb8899ba1e9f6ecfb76aa465ec12645c0a151"
    $a5="27d1ca9e380f2d4224b5d8505a5715ceec6fca3b03be5a0d38344ab2fec2b116"
    $a6="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a7="df4738b4ed2274b73722607a4d1cc2158eb209ef16b350087d867393f98db685"
    $a8="97366c98ecc5c51c039bf7d2aba720a0c348e5843f136182fa72337c61e28a26"
    $a9="069527e6c0cd6b8c31aec08972a6839e69bdc571f5d95700c1054da7966b1b3f"
    $a10="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}