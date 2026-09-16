rule sha3_512_hashed_default_creds_wago
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wago."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="effcbbfefd6c2529bf7a6a08c0079a07369eb582d7ea8c2e19f33ca800da4d8a4a21cef109e9043d6e80f63c9230a11661a3642e2f3bae2fa3447b702b9fad1f"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a3="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a4="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a6="548ff3bcdbaf24d9b020a04851119b8cbb8103c7c4d61acfd306fcd4c357a50e5afa3baf6ca2e9d47d00a30a76eab3d42d8ee052e11802a72a06398731f60636"
    $a7="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a8="be91c99aaec923942c102419395c9a8e5aa85d323cc97f5338f370c48bd41525fc03c6919e52fe3abb5859fe36a3b47d48af535167b38a7bf5bc0486bd5ca9e3"
    $a9="a09b4a3360b01fd5cfa214fe52fa2a62795b43175e8cf8dbf373b5b591852a296d4f7d75e4bd0d4cc77c954927c048055c4db3522b8745aad627bc62fd1982c2"
    $a10="effcbbfefd6c2529bf7a6a08c0079a07369eb582d7ea8c2e19f33ca800da4d8a4a21cef109e9043d6e80f63c9230a11661a3642e2f3bae2fa3447b702b9fad1f"
    $a11="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}