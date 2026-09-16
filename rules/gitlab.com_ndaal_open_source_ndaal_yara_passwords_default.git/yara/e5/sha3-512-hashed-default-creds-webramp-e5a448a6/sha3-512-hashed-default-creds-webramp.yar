rule sha3_512_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="99dc9dc4bcce4114d806b9223f839b69c9e4ce5e1af56cbfc0db17ad2e6850346e1ee3b8b3105b6fa7953783f3ffd98a48e96755b2a4635e3fc76ddee63332aa"
    $a1="ba3460952aa6083903cb2cfd03d005fd3dda1e74b26893e214e9aff6148beb61b294c1399a751c59136b3d467aa60fbcf7a276944362ff760edf525dfbbc47c0"
    $a2="8c9a1c3bb8d407b9f37f5a7a855914aa34b7af09ac0f66df7739a8cb07b9234fcbca89ad36804b270a76a09c3a929dc2ed852e4a30d95722e5cf5055d5e32874"
    $a3="ba3460952aa6083903cb2cfd03d005fd3dda1e74b26893e214e9aff6148beb61b294c1399a751c59136b3d467aa60fbcf7a276944362ff760edf525dfbbc47c0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}