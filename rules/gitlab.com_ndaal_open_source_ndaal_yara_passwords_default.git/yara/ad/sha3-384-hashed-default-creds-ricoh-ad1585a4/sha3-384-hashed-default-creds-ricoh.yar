rule sha3_384_hashed_default_creds_ricoh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ricoh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="f5276408a10d9c8841ac9fc0a3002818b5d55ef8065c3dca312cf764e4ef7213ae21d3f35423123de91061a2ee8a0bb5"
    $a4="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a5="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}