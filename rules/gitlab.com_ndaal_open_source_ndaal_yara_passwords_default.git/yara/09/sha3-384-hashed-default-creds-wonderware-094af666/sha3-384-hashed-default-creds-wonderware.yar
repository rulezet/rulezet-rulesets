rule sha3_384_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abcdacf95c73a673752b80f81a6698d0f92e670e60c26fed27c5d478a8df8b1d7cc276a865f957f2a38ec0af972f98b3"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="2c3065e4f1752aadfbd3310d789685da6153be80162c7354fd2cb3916bd1219fb5d3623d4190be1fd4d57bf834ddabbe"
    $a3="465cb17b0721439b7300e4a15ef6dbea00adb9fd83b771db27ce7ca18fd02b99e124d791d37ee8f6e15aaed682bf18a5"
    $a4="2c3065e4f1752aadfbd3310d789685da6153be80162c7354fd2cb3916bd1219fb5d3623d4190be1fd4d57bf834ddabbe"
    $a5="ae9dc843406ba66e6c1a9bb7e578a5776e5bb4ae3e99ea44c5a921f51cd08675edf78e98f7a74b045f7c9c7c1fbf416c"
    $a6="ff30133501f6e021c8522e859a539054e0c5687be48078e0dfdec7a27e39cc1ba4bd9cd5a823acf59106f659c4991f23"
    $a7="6f9a9fdc7d7b5246044db1763aa24004f037ede2d51c811b6f0d920c3e6c529e4b972c9152892ca4f89a8e41b15fe116"
    $a8="9e4ebdcd2cfcd32fe22b92cf375b7e5a20f78bb95be8ad917dd9f4fdaae682bb1d8a3b95ddf33ce8344a6eb3ef2c3d8a"
    $a9="9e4ebdcd2cfcd32fe22b92cf375b7e5a20f78bb95be8ad917dd9f4fdaae682bb1d8a3b95ddf33ce8344a6eb3ef2c3d8a"
    $a10="71d5542491db8c3c1bf16a70b52ecfcb6befa8f839886f4de91f684d27eb9a88189d8720a1fc9c90343bb32ae06c6c33"
    $a11="816b2d96d13982ff3fcdafe3350b518de8bba9ff846abf0e5174798698a0a188d6cea0a4f6a3fa9cb7886fc821d41b8e"
    $a12="9573f16637b9daa84dad3f4064cfbadee2f2790541b804d3e7c19d4b8d5ca16684bbcb1a5c8a71bbbc8d75363e88f05d"
    $a13="9573f16637b9daa84dad3f4064cfbadee2f2790541b804d3e7c19d4b8d5ca16684bbcb1a5c8a71bbbc8d75363e88f05d"
    $a14="b59ba699558c17b82c7a9435692291af1bc574c7fcc9a338d9882bff4df733ec0ae5cc700e56ffbfd6f5a371f00e15e4"
    $a15="dbcd9ce419de210b5a6b7d25cc22b0ebc885a0a26848cbd3d0c41681248310818633e4b39775881f3290a54378ae5cde"
    $a16="fa2c9e767d3703086d289f145e76d82936f3ca1a94ff4bfa4fae0679a1f180e2cc6277408ab865da831f7945fc3ab39e"
    $a17="fa2c9e767d3703086d289f145e76d82936f3ca1a94ff4bfa4fae0679a1f180e2cc6277408ab865da831f7945fc3ab39e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}