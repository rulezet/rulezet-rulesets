rule sha3_512_hashed_default_creds_adobe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="15842be569bcb206b002b67c5e9f7f9a34373a43069870e44eedb93c270c3d25142a73496bf85d164a41cfc6f72c170d1a9a206ace8e2453ba22dbe237fe0915"
    $a3="15842be569bcb206b002b67c5e9f7f9a34373a43069870e44eedb93c270c3d25142a73496bf85d164a41cfc6f72c170d1a9a206ace8e2453ba22dbe237fe0915"
    $a4="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a5="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a6="74de1ba9332e7a704527759f67ffa17e66eb5a1bfabfbc84a22999d53f39669685c8648fbd93509545c65806bc81b43b6ef1273037eeda37973a3a5c26a10f07"
    $a7="dc01ca560ea2644e4232bacfad5ddc9eec1efe742d78d05ec04d380a429c9aca5354081d08f100c7dddf0ace72ede5a3cd899f7a7aa54751467648af5b294dfb"
    $a8="d27f1d0975973a6da7d4baaded8ee04956ef9318e02ea058383911ddb85b85831092ab3a6e446bd4034b94fa8d4f344e34fcbe37619cd9a3325e49aa9c2b8da3"
    $a9="37af09ce69e7116dc485328e29ed178888ba86c2a3fbdbbeb5290b987d78bb5d3ff6859de62b434812c768addcd2a6b9d6f98fa4a912384633eeac8a49d6ed53"
    $a10="b0c9cedef88b21548152b42367e68380003dea6464df8b9a4950e23a73d87eb9579a2574e00b09dd5571dcb11e33727d240817463b4ec72d9cd47f99afb7e85b"
    $a11="b0c9cedef88b21548152b42367e68380003dea6464df8b9a4950e23a73d87eb9579a2574e00b09dd5571dcb11e33727d240817463b4ec72d9cd47f99afb7e85b"
    $a12="e31ca32f678240300ece9a964fd5777ad310fad2ffbd7a37de7af31433169c54147b88f0c38a74f2dbaadb82c753999709f9f2fe216ac96458338f5eb76559cf"
    $a13="e31ca32f678240300ece9a964fd5777ad310fad2ffbd7a37de7af31433169c54147b88f0c38a74f2dbaadb82c753999709f9f2fe216ac96458338f5eb76559cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}