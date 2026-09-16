rule sha3_512_hashed_default_creds_ramp_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ramp_networks."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c9a1c3bb8d407b9f37f5a7a855914aa34b7af09ac0f66df7739a8cb07b9234fcbca89ad36804b270a76a09c3a929dc2ed852e4a30d95722e5cf5055d5e32874"
    $a1="ba3460952aa6083903cb2cfd03d005fd3dda1e74b26893e214e9aff6148beb61b294c1399a751c59136b3d467aa60fbcf7a276944362ff760edf525dfbbc47c0"
condition:
    ($a0 and $a1)
}