rule sha3_512_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c98fa2e674d0a618afe0edf9bfa088381afbfe02606e86c5fa8914f6e350edd429d2042039d52dd42ff84d1ce5a4e8fdea0d4b7f280471a4df974d59d86fe0a8"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="3b7c05400a18cdf135a1b0290f289fcbe91417feee27c19c1b55a3ad47feb3af57912ef0464348f284cf58df13a9f022f5ae443214195559001910fe91a402e2"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="0ed32913df4202a950324028dcda00567688bbc02bd6e2865cd415c9787d1e0cf64f5f7eb437fc330afd680e7a89f6afa07ffcfc1d45daa8a44177c2bdebd64e"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="17a5fb73c757dc1463d52e61d0bd51b4c49b4b557e1c6cd66f1ca2e49b9fd9fb5f93299e2f944af3c3183aa0a29e353c31efc049bae6c91e5be2845beec1fb63"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="ad77694977fadbae8890c9bc01653f4ea060598472734533136a6e5c3b2469fc6ccdc8eb6ca9ee3810f0a9c4b98349286bfe9d1e0f965fbcbdf1515233bcdb6b"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}