rule sha3_384_hashed_default_creds_watchguard
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for watchguard."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="36d841bb32fc5ef1a5704652097584ee789f4d2e745fa283516320163dba0d699b5a502de4f33321155dc5715e0c1e4d"
    $a1="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="efd9e5ef02a9405c6da4dd3b8451f61834c6c444d2ff6654a29a2c4709e69d98815377874349b9d9189f72527b2216df"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="0e08ace98462c032a1d1ef35387532a39d62bf837abfdfd1ac221c6a070fe0e064ce07d88c6004e63d55d1fa8d508327"
    $a7="9af28d366e58609cf8d8d6bb3479614fef9eaddc93a5e291d7982629f0042dcc2361ddce35753e3e96aee091051d23d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}