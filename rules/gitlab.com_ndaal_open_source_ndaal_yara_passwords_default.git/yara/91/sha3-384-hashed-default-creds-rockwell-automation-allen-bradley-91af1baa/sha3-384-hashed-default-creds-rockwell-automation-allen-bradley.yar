rule sha3_384_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="bfbd0f3e3c470c2d3976e44e9558efd84f44cb298851d82c15f3d8864d2d257fdbe17707389550d48f82c9bf30f3cd56"
    $a5="19df6fb1afa3ece8907b0af4c1fb24703e7c2b8202810a2d0ee78f1395d0eaeb729f30f7eef9ca9a93fa6bfa8c65a83c"
    $a6="bfbd0f3e3c470c2d3976e44e9558efd84f44cb298851d82c15f3d8864d2d257fdbe17707389550d48f82c9bf30f3cd56"
    $a7="b2de79279ff8193fdd6b393af4e9f696650cd6a84464ad5489aada4beea3ee46dfda60e8cfec1b9619af35a7870b4ba5"
    $a8="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a9="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a10="cce720412c2ef8bc3d3382ccd9741a66b90f9d88f4c0e92fc774fb896a5760fcac3057896992c955319e2837ea80ec18"
    $a11="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
    $a12="0f8baed846a780b070317ce98573c44d035f2d6779457dbc699fa8794cd582cb596b04f18fa4cf7a16e22ca986ae365d"
    $a13="b7f6725fa11ad8f24688dd3d1250f0423c796160c8e6d05a33b32ec01090c84f7801dff0262eddce3e32c3bde3b620cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}