rule sha256_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a1="6f166e778d3e08c067dfe733f47e38f74c59817c268e7ec633c74d34e6deb56f"
    $a2="8189746886056ee6d6fd972305266512644d5160ebf412fe049157d4458a2a36"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="92563d2553584ef62ef475e3600bb4acb6c40ebd3ba5262e764272a05074a7f2"
    $a7="d489934ca5788e0ef6804a876ccebc50a28fc28496c801e1c3e91ca3143abf0b"
    $a8="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="f1526f532045c9600c2b534540dbda26555cf48acfff3425c1be20ea238867b0"
    $a11="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a12="324dc0fc79e6ed2f5ba548e90d23e7600e5a7d0cf072dc2dbe17013d66534551"
    $a13="f73c1c8e2facc4b6f4cacc8ec891c55c2f7363bb9f84ebd007e7c947d63381f3"
    $a14="3a5364b82c10fd33a3676e2e99ef5b46d8c93c9ecf115ebbeb09d5adde45fe47"
    $a15="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a16="89292d1b3103ac3cd6a0dec5c9168e9b636e8e0346c940bcea67d1c343a97585"
    $a17="37a8eec1ce19687d132fe29051dca629d164e2c4958ba141d5f4133a33f0688f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}