rule sha3_384_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="a71433cf354d756a50d1560dfd585429808a30a890d14855d90f3aec12309f51dcfe603539ebe52295ae3102b5b80fbe"
    $a3="07998ba419e8546fae0d5b6643c82b92de5f8e853ac8be82dd855482729fa0ac0af1f0b922f2cfef80742163790af136"
    $a4="045762f9bf939a8d32a5590b66349d6769208c3c62338c34d5ac23cbb776c14c028dfb51bd5a8b699ab7d47946eb66c9"
    $a5="84d4794f63cb8fdfdcd14304f90ec6ba0522fecd32be8f8dade888363d96669b92dd28facd02716c190847d8a583a9aa"
    $a6="e6baae9bd4c39850290f7930a816eb2e0806b267fc92994cc97c8595d7ba2d0ee5f921b1c980b3d7eab3e463613875e1"
    $a7="84d4794f63cb8fdfdcd14304f90ec6ba0522fecd32be8f8dade888363d96669b92dd28facd02716c190847d8a583a9aa"
    $a8="56fbcb8d24edc82497a4c8cd2cdb841a2aa15222133bbeed7582a907ba044cc70b01a74fa41ba74edfca8ad56c5e2ca0"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a10="420677fb158e8c3207566ddda5f7983239b89f99d2229fb03594b034cdc3d7f3a2253f202fe89931b7953bea6497ae5f"
    $a11="07bc09b5d98a45b3a068a1b342c86374b5a5be23a847e706ac5e7827e273fad1baff63eb5f68424efac7f596b5471f9a"
    $a12="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a13="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a14="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a15="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a16="dcb22c52c5e8f8cfe975565f5397b4dd7d6b786fd378eafbf93825820b45e53f49056bbe5a7380db128f150815dc5e84"
    $a17="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}