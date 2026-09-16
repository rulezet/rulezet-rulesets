rule blake2s_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04449e92c9a7657ef2d677b8ef9da46c088f13575ea887e4818fc455a2bca500"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90"
    $a3="3a4e065942271be19db7bb975a4a363dc11e7ea02453898d8b5b1f5abb053a1b"
    $a4="04449e92c9a7657ef2d677b8ef9da46c088f13575ea887e4818fc455a2bca500"
    $a5="c03258055c94b6d7d05cc8efad49e26c5237b0de0ddf310a61391fd7c2a4c6a9"
    $a6="9c5889e3ab01635e2936b93aa64f15c1d781f1bb7b64d3640c67d25ed88dd269"
    $a7="230eaa3c2f7592c72c4588a17df09891a75557a9a87834492d1450aa96e605ef"
    $a8="347ed3dbac3394d262bd9b09a97a838e4c8391c8ec8b805b052ef3cac4d046f0"
    $a9="3bc17eca8fa9740a52bad0b3b574278320fe47c58969edd3eddc9544bdeeb7c9"
    $a10="2ec3cec278cccb2b2b2cfb246125cf41e2c0323156012c08bfb8ad7bfdc3c8ff"
    $a11="8ae2b4d552ccaf1c6e0388efeac25a6f222e90948563439f2c681fb1f5010ee8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}