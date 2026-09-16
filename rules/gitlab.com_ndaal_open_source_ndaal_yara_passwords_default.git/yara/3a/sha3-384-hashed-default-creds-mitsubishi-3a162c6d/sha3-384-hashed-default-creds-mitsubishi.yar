rule sha3_384_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e99e97d7bae314cda30b32c6dea69e9d0ede5e08bb6cc6e148b1a906b4918f505160039e75d88fae822feca6c1b6ceec"
    $a1="e99e97d7bae314cda30b32c6dea69e9d0ede5e08bb6cc6e148b1a906b4918f505160039e75d88fae822feca6c1b6ceec"
    $a2="fa0e7a2411343289471cb5b4ce2e5dfff1c5a7ddab97f16df343010ddeb0abc9004dd34711ff790e75b7e378228b4346"
    $a3="fa0e7a2411343289471cb5b4ce2e5dfff1c5a7ddab97f16df343010ddeb0abc9004dd34711ff790e75b7e378228b4346"
    $a4="e956d70ef6cb655b32bc47b4e15e316c2dd2f8e40d3f989d302f5427e563f5add6fcc428fd4597e7353625d99f42ca2f"
    $a5="8a95ee7f3fdfdee68288a25c947a6f8f13f7ae84760faeec41339eb9d548131483a95668b704a6bf83a509c0990cfc41"
    $a6="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a7="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}