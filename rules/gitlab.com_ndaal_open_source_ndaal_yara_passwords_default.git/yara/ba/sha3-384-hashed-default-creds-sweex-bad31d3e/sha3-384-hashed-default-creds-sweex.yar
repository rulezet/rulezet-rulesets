rule sha3_384_hashed_default_creds_sweex
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sweex."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab33c5631e10e1b6039c54c9db2d43be1eaab964066f89ff42201d6528df5cab213d2ab4421c8427e2b5338971af4cd9"
    $a1="f456f8a04d373f0a4e18faa5b06f6b46ce00d05ac5c1f84e6f69c65da649647ad659bae5b65c7933e106acd5ae669954"
    $a2="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="742f12e0aca6501a72089aace68a8eec168b18fda318ba2e87ae0ed5046cb1afa206229a2e871d459359649efb5eec5e"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
    $a7="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}