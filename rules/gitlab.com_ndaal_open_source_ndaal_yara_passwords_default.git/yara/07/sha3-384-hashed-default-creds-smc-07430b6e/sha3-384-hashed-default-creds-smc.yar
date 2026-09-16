rule sha3_384_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a1="597796fc80368aa98896760b7a2c66de525e5472ffdea59875a4eed2c9b28d8e3840003feb7e3f5124c964fc7632a08e"
    $a2="c488bc88d9a5f41f36fa285cc2b44f8e6f9b171f33be64daf3a74adac3d555b241ff898ba8043f86c17acdefb359c1d0"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="1d243ea48da2020cde4f09bd8d38a01876f099d53bacb37cffed21309dd399c9cd57a4dfa671c06ab2627c6eb5e23f99"
    $a7="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a8="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="05d9c92c08531748c1752a9a1d7db2ef4558edfd7080e16d3c3d146c84b5e92c9ee08042191812130a35786a234a2014"
    $a11="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a12="e40da1fc6ecbaaed8050379007e33d86bb116367495b90bf7bdd1dc93c3b5578a42f883e1ea9061ab8ce45e895f08c52"
    $a13="8297ad20b40298518832407380132303d05a61a28c2009d16839b0b461188c3bf81df28c0082f0830049ce4a439ae7e0"
    $a14="0429da6051634207233ce1e7a6f5dbd59e56b606138bf1c8b0dba1729129fbf482d3f0ae2804ccdc1ab485dd073a060d"
    $a15="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a16="99c6b10c4aed4f0d55b9ba3a13ee2bc67207fd3bfb3969cf04449b4630d87885844fa701f0eb6aff43b84242182e632b"
    $a17="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}