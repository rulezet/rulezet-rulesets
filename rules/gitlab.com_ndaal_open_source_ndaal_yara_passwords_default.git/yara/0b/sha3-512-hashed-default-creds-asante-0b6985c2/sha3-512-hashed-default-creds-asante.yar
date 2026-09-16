rule sha3_512_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0dcc3b9c586e11be5146f5bb0100734f0b45cec891e26a7d2a166bff64258c1d44002cd143521f7deb3a685b284fe7d4d7dfe43c00858cbeac283948d80eeac4"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="0dcc3b9c586e11be5146f5bb0100734f0b45cec891e26a7d2a166bff64258c1d44002cd143521f7deb3a685b284fe7d4d7dfe43c00858cbeac283948d80eeac4"
    $a3="8ca722b033b8e0f65c3373879389c8265599889ba6ff331528f1543a804cd2a1692573b0a09be80e70f7ed8a49958cc2da2d04cde5d0d3d0ac56dc246aa05481"
    $a4="23bcd02f19831595b52c406554bb267e95df45ee00f6319ea5d36297f0988dc70a0bc04b3534794b47888f63469934508531c157cb52138b4f1c44f212d82a6e"
    $a5="a76eaefd97aaf8c84ecc4952505db296edb3a92730f3c1fe5f7f2f8dd8bea02c0180d31178db0fbcb03d5a01328b7e5f4d44a2d3cbaa033a30397b6de944fc36"
    $a6="23bcd02f19831595b52c406554bb267e95df45ee00f6319ea5d36297f0988dc70a0bc04b3534794b47888f63469934508531c157cb52138b4f1c44f212d82a6e"
    $a7="115e96ee49d3cf341f25c038acad769180b421e61c4b834d99b9f4dddd7e6e03141a2d84ac5af8878ac7cbb758fad78c66f1b1d7e3eed6087cfb9522702efa39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}