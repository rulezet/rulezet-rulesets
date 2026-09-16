rule sha512_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9726a7d64d06944a70e07628223540ec86534ed18f8332990e60fa8deada98046acefbcf7e9c3e54082a00ac6ec499b264f0f77de6601a1fc170b57ea2b479d9"
    $a1="9726a7d64d06944a70e07628223540ec86534ed18f8332990e60fa8deada98046acefbcf7e9c3e54082a00ac6ec499b264f0f77de6601a1fc170b57ea2b479d9"
condition:
    ($a0 and $a1)
}