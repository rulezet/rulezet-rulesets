rule sha3_384_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09115bb74c0f96f7e0afc093d1343c10e8f97a5ade755b5e3add1dd2ea4c5c11f6c0d8040aedc090e86ff68eee98da1f"
    $a1="d1ef2e826150dddff72c5b643142f61c25b0e529961693fdea0c2f3f7e9fe3d422bf5713d43d632acbc44dc7c7724495"
    $a2="9e67fc27dc82a040f4d69afb4f21404ddc2939a6596f898eb849afdff339bf4021424076a0c9abedde240ec9c9f743c1"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="f3e35699f5b5c65615b9b77e56cf9a027927da2779f7e249a2971408801ee28c739c2de9b95a8bfc94647e1033239a71"
    $a7="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a8="31b5e246ef3f10c8f47695ae15579dfbafded3cd41cdc02a2610c519e9adfa34352a60db6e6caaab5cb6430c52e2e478"
    $a9="9f2d4fa5d014018b928656b25ba1bb19c8c30c99608f41f03ce47d63ae09cd9a87efaf5fb4b93fa21db220ef57c412c2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}