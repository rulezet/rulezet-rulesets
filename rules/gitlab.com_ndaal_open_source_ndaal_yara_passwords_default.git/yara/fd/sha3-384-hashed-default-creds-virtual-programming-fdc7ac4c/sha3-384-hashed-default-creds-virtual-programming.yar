rule sha3_384_hashed_default_creds_virtual_programming
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for virtual_programming."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="56777b19d7dfb1801a7f8c90ed152a737854a973496486d3ff8ddc0c2e1650bec2ecb0163c1915cc2bebfd7cf59fbf80"
    $a3="56777b19d7dfb1801a7f8c90ed152a737854a973496486d3ff8ddc0c2e1650bec2ecb0163c1915cc2bebfd7cf59fbf80"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}