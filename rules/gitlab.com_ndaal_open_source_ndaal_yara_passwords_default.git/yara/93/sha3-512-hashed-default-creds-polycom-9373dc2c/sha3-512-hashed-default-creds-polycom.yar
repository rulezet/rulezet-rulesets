rule sha3_512_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
    $a1="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a2="8b60ce07a45624f930298d133aacb304924320cd4829c352a1dc38514299d633e37ecc5ecb90987d01273ac9709e4fe9bd496577dd2337f37526f1c5ad872591"
    $a3="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a4="ce997a8d374571ab2f8c2ac59af15841a1518dbbecb473dd04a73c3a2ba3631aa5274026b136362e694ee211ea27dec883cd2610638127cb7ca5f77e2fab2c29"
    $a5="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a6="a1c449c96bd5a44824f19a7131ee2545b218541a49f10a5708addab3f6adbe66569a7741f310da4161997edfb1c7314bd2f2b81f5eff0ebd8c57faade572943d"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="a04c522832688f86f66bb9811bc69084dc7c918044c72bbdf6b87953d0cddc2952948b46c6aadce9ef8bcb62f250a837e7a7825f3468fc9415f22896dd42d6d0"
    $a9="4f6b6d857af55d36973103520182a3f1aac2361408cb404e6b283b66b626a674671d47c352fb90206a188304843da991d7df8d2c98a9743d5aebcb307f8a5e88"
    $a10="0fe220a126aeb06ab687b5cf73175abbd6194f57b593059f33186d72066a283af765cbbea04cae0bce0ce793116a4ac99424c28ea7fded4e88a18cfc51513cd4"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}