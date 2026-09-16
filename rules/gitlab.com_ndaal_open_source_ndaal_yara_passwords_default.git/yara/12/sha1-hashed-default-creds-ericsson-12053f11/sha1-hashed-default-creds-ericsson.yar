rule sha1_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
    $a1="3aa24562e5ddbc02f7354d04ce68e0983ca1ef7b"
    $a2="7505d64a54e061b7acd54ccd58b49dc43500b635"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="92005ecf3788faea8346a7919fba0232188561ab"
    $a5="1ad692285750b58b6d8e1b3acdfb649874b6ba50"
    $a6="b780d252a12c8c472099c589d729a6d60a27dc7b"
    $a7="b780d252a12c8c472099c589d729a6d60a27dc7b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}