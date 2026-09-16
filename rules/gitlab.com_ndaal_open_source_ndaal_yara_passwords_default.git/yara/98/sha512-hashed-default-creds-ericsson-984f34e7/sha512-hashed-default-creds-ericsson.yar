rule sha512_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
    $a1="9776ff6e746cc815066e024ad18130c1b9acf5d45c9afedabd831c0656a7011a103e2d9d659747456e62b6098205eed4cee616cb57122cf8a9e5eeee07d63fe8"
    $a2="1625cdb75d25d9f699fd2779f44095b6e320767f606f095eb7edab5581e9e3441adbb0d628832f7dc4574a77a382973ce22911b7e4df2a9d2c693826bbd125bc"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="5766d45bdba1152105abfd9662e551401a9756f1a37b3a3669ac590390479e9220591027098d61eff70ed6d0314d2cac7128f488df052ed7318ead76ba5f2f7b"
    $a5="4fd54a51b6680ee7cf925e084aa10576a46213cda660c2367898b31f545b2fb24b69dc7c4c7fc252d75a333e57a1432878641ff6ea0b8b0547cae85779a34e0e"
    $a6="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
    $a7="585d09bbd0230435c6600fbc2f9858c6878b183b024f459c5e11f389106e835528423846ee0cfeab5ee870288bae56f2ff052a7942ddcb2ebfcb91e6664ac2bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}