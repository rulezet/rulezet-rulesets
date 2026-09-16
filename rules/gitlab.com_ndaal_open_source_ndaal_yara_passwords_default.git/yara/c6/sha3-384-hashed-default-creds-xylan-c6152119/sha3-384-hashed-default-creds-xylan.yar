rule sha3_384_hashed_default_creds_xylan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xylan."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="d245abad420995115064295eb5e440e3eae238d75065c3c1efed264118e66c4c4bcd15e3e8f37fe14ac99709e7d6938f"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="d245abad420995115064295eb5e440e3eae238d75065c3c1efed264118e66c4c4bcd15e3e8f37fe14ac99709e7d6938f"
    $a5="7810f88c4a73bafa6d9bd91bc670d086413e8c3a4c225c314d81d2059a5c56debe060b612a733b99eda38ed75c73716b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}