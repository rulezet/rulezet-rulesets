rule sha3_384_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a1="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a2="c6afc90044c10cb59276a11284d4e6ee86580691ede399641caf85c110d87e7ed72208b5983e185dc8526bb988d2c1cc"
    $a3="dbc5290bbeac891fe6f56a3b537a318a3a3c5cbfb5cc08995aad9e9dda73c9909b365af079b523538d6f6699c68b52de"
    $a4="5b85d6d6abee0cd02c8e86e8f1582d66d40b91b7f0fb1e1862ee6fef4ab11b2b87d9f5093958248a7677dd7c2ba5eba7"
    $a5="9c22d5ae545171c67130105247577cdfdd60ee834953cd65f26a3598e1dc72944e94280b1a10a73d64b4f222b9a59ccc"
    $a6="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a7="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a8="c3e535e3b57e3b4f9dbb9fe73e0fe8553c95693a26c069f26ffcffa2fd86e82fe2ad78de17cfd110a14e26e8df3ee511"
    $a9="21dcfeb22afdbaaf2df9907e068c052fd118674b27889c88eda4e2e521f7646635606e2957a0e5613041c2adb8ae2e04"
    $a10="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}