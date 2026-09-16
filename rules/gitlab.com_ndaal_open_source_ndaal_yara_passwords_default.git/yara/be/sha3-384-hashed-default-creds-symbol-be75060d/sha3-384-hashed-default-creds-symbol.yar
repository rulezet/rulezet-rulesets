rule sha3_384_hashed_default_creds_symbol
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symbol."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d931599da33a102b3c326872e9acd7608dc0251fea000f49bd2e3dcba99c441270cca1906a6df8900f1f8d291c26db06"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="511f3077273b59714ac47f5e96151acd6d9ecac08516ecee10676e8a383f736f4817f6287d37d08c055098beaeec0025"
    $a3="511f3077273b59714ac47f5e96151acd6d9ecac08516ecee10676e8a383f736f4817f6287d37d08c055098beaeec0025"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}