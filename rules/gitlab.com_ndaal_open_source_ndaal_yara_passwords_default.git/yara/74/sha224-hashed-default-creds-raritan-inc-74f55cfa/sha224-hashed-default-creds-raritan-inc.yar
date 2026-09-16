rule sha224_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bef8463d6d042e951dae3906ec0cd092029223b073b8634b64d0783f"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="bef8463d6d042e951dae3906ec0cd092029223b073b8634b64d0783f"
    $a3="1d7f29bd053ea244cb4c39d4b4758d68868e7fe0d5031c3202b30b4b"
    $a4="2273f31a2ce0171d91a63943138149edcb17ee3f9bf248398506b7ee"
    $a5="a9e31f5c79585cc6de4f60c1658af408180f23e41cf4a2f1c4b9d0a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}