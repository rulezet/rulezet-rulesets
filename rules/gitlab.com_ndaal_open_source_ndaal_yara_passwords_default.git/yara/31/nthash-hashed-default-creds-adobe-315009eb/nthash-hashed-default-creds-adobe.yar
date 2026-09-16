rule nthash_hashed_default_creds_adobe
{
    meta:
        id = "6dNH14Z3pqnch18NZNPTH"
        fingerprint = "ba08d7073ea96b870e1790f5aab90fe64648f00c747e00783ada446c74766b79"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adobe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="dab0d9d3d7da0c32e595a1c554a8493b"
    $a3="dab0d9d3d7da0c32e595a1c554a8493b"
    $a4="4481b934fc9cad79cb0f5295fa8cfc98"
    $a5="4481b934fc9cad79cb0f5295fa8cfc98"
    $a6="8bedde4d0859dcb33707d68ac04e83eb"
    $a7="8ba791415ae4e270b3be0a84d2d59a41"
    $a8="90a67c6a62ef09962352d19bee9b11e7"
    $a9="78f19ec54a4df0b7a4008b6346412278"
    $a10="4140eeae472848ad4bc17aeb028190b3"
    $a11="4140eeae472848ad4bc17aeb028190b3"
    $a12="ffa9067ce5b6b2466d66fa1c61c29676"
    $a13="ffa9067ce5b6b2466d66fa1c61c29676"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}