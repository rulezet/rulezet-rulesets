rule sha3_384_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a1="68c89b100df772d7806b9982b14678f8ca83f8ff0e17a6f95ab3bf3274564afad4fdb1378c80a48aeecb8131fbe89a24"
    $a2="f437f71603b12fec1a4c1cdf46af48d0274fc3da86d451c00285697137cd82fb803b543f025e4d4549eb5efb514643c8"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="fbee00eab192ea52017accdefa65aa541c49bf1e5133d8ddea9f185e14cb17fe3ce3f725360a6a24b69fc6242f5073bd"
    $a5="e758cd128de8a0266eb9460c1a91f2046c454c37e47153a5b4f2d8717d287cf907890d82983817b7166ae4cd14ea014e"
    $a6="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
    $a7="28066f4563d83e69c2809650f859ca2c6a97b97de635afda527e62ed8660201c6a3c3acd07505bf151da7402896ca1ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}