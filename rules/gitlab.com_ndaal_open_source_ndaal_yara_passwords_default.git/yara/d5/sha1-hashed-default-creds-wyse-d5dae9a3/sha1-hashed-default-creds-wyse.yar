rule sha1_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8ecf50d08b30f68eccafc3532bb9c9fcc5bdd75"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="9607639aef7e6cbd2a2757d9efe3306228ce81c1"
    $a3="8a77613b475e46064321fd7da18d126ee35e5066"
    $a4="957b77b65a6526c830b17799cf87e639ef6c230f"
    $a5="d6f772f88778b22626d2b862a14a46148185778e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}