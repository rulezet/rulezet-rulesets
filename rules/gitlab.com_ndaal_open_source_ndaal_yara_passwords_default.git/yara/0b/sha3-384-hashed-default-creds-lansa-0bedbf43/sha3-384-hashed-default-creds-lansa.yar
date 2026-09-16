rule sha3_384_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="ed9cab2db005ef146bbccb7a49802a5543820c50ee387c7c45eaa15a7ef3996b192c4ecbddb8e06ba01c8b00fb59603d"
    $a3="ed9cab2db005ef146bbccb7a49802a5543820c50ee387c7c45eaa15a7ef3996b192c4ecbddb8e06ba01c8b00fb59603d"
    $a4="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a5="794ece98694decde610eab7ff5d0019cc61e85a7aa9c1524c4be2b99c76744446fadd7969bd4394b42601c27b993ea23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}