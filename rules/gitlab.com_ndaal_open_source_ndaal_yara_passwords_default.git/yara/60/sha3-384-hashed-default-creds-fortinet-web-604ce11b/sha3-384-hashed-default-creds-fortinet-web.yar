rule sha3_384_hashed_default_creds_fortinet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fortinet_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="2939d842fe82d218507180743a8a8cfc81077eeaed6c2fa16a1991a89aceaad75195d52ae952b05fbc746528336893ad"
    $a2="39ee09b7b153363feae200ce57926aa050ef3ffe1720fa89d6bf63896b621e843193370b7f30491e639128d62bfbf046"
    $a3="2939d842fe82d218507180743a8a8cfc81077eeaed6c2fa16a1991a89aceaad75195d52ae952b05fbc746528336893ad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}