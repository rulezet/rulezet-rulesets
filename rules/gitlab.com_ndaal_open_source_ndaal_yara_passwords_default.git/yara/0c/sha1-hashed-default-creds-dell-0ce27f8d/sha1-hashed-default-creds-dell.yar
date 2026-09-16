rule sha1_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb654ac8f36f840016f043aa3e4e06796529704d"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="dc708fbf646cd5c3b73f82a2946294a2d1f9fac4"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="dc004fc311edc14e3686134a1c7655842059d856"
    $a9="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a10="957b77b65a6526c830b17799cf87e639ef6c230f"
    $a11="d6f772f88778b22626d2b862a14a46148185778e"
    $a12="d8ecf50d08b30f68eccafc3532bb9c9fcc5bdd75"
    $a13="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a14="9607639aef7e6cbd2a2757d9efe3306228ce81c1"
    $a15="8a77613b475e46064321fd7da18d126ee35e5066"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}