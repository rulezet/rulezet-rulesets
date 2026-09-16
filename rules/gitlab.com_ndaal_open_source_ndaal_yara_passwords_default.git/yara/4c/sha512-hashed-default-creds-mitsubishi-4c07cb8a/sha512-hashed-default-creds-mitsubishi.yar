rule sha512_hashed_default_creds_mitsubishi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitsubishi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e31db536865c0db7745ff6fd3c063d373149140c729f51c9771046615fe27d3e96796c40a3a329fe5c51970e1c8fda216e36f17714a260cb10d1badc89a7489"
    $a1="8e31db536865c0db7745ff6fd3c063d373149140c729f51c9771046615fe27d3e96796c40a3a329fe5c51970e1c8fda216e36f17714a260cb10d1badc89a7489"
    $a2="deba6ff0c2f0c2299b0b676e42f2b36a599ed6db2d864b7c85f28898ef36b7b29505fa89a4d41c6d97702fa367d5c4b3b03d65f5feeb777b5b67046b4137e086"
    $a3="deba6ff0c2f0c2299b0b676e42f2b36a599ed6db2d864b7c85f28898ef36b7b29505fa89a4d41c6d97702fa367d5c4b3b03d65f5feeb777b5b67046b4137e086"
    $a4="85336f9d2134e4e28f47ab082c7e01c95fe0a230b8ab8f95016765fcd9d6ff688481a2c3541e5fa166aedee259e755ddd17158eb4aae76a2033956c8b805ba4b"
    $a5="b0d21a54f973ec5ea25bbb8bf96fb91fad30ed785661d204bbffe002a069475b767dc1608497598ed04e1c59f510b782362489291f4a6ed4dc78f513ede26845"
    $a6="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a7="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}