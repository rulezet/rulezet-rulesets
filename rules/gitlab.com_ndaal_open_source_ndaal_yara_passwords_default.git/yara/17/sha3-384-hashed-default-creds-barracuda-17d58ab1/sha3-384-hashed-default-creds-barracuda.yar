rule sha3_384_hashed_default_creds_barracuda
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="2f94fdce4be568429b426710b3a36ee7b9b0120b6ceebec53ef2c0c9248ea55b07bc9b57be9816119df4849cd2e126cc"
    $a3="2f94fdce4be568429b426710b3a36ee7b9b0120b6ceebec53ef2c0c9248ea55b07bc9b57be9816119df4849cd2e126cc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}