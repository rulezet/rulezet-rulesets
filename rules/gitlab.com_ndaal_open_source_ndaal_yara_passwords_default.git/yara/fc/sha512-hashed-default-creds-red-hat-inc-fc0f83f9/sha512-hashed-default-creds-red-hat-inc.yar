rule sha512_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a3="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
    $a4="2e96772232487fb3a058d58f2c310023e07e4017c94d56cc5fae4b54b44605f42a75b0b1f358991f8c6cbe9b68b64e5b2a09d0ad23fcac07ee9a9198a745e1d5"
    $a5="32c1a3cb5d6b258740c07295e20761f08623af0fe419e81ce1bbcd42a4cfcd251405c6efa1b4ef32a128f6a58da35821c3efc1ff955bcfa671ec05ad43268d40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}