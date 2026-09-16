rule blake2b_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a1="20ab24778b723106269c870575c7463ee0ca0d8a6e1e338ad1dc4ff7a89606f7375e04ae4c768892d48991c7b8d2e6720fb39edb86a772e3e7adf723cc8fcb39"
    $a2="6740ad43869a805dc9fd6ada5e556bd7dbf0ff27596827eb174e052c61d14ba087677a8872a2d229d8321943ab4ab759d6c74de0a34631149d48dbdb0dbb8e91"
    $a3="b2ad3eae8f8dae047dfccc34afb109d363a895cc71e0540252d6fe37c2674aab2baf21f5b5b2089e7778ffc4165e816da36bb520a0d3ffff0259d14b7783a38a"
    $a4="bd4312ebc64e5aa86e3e8a952b14243c47deb93abb9fe2652679fec67629220868e7d3ac72c9308d119ce3208309ca73d426d350520f8fb33c6133e2e606d8fe"
    $a5="840a88e800876bc4e40f8c33d9e7c293c0e28f48c291398236764b0ba716c09a0276cb798e83f10415341cfc7889802accbeda169135716ba316d0c4afed80a7"
    $a6="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a7="0b38c93bb2e46b2037c88ddccad59cbe1092f2ee7eb24ece6381de92d02f323865d52ac3d5a2a7da513661224b910c258184a1bbe405c9ebe1eabd83633f1e5d"
    $a8="5e759101c609f4b740ef80e765ae365b2af502d28946ffdb14a008ba3b8f3b38d22724597db1a2727631e47be95bf3dbc91421426b178885abb756996aa2ed28"
    $a9="8f439c2423e8065f171eb05842f7b04dfdbe2f22dbfa356edc37c0c3c292c1127dbebeb13fd9bf2fe04e47445d5913545b1702c1358df1e80f5610ba0671167b"
    $a10="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}