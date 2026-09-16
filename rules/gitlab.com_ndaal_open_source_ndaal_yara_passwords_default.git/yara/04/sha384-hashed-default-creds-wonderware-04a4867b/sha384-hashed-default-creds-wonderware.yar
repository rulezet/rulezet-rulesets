rule sha384_hashed_default_creds_wonderware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1df528b21e7ac5ab001872e8dea47f4b23ced3a3c517843b441ffd7a114971f1de72ba993394205b5ab05e0b0170a39b"
    $a1="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a2="745c22ae2124abbb3f9c5728f558a6459d9d44e9f0323f0afa476ce00550ee8de2d4da7d7e696ed91f1e426e113f21bc"
    $a3="3b06a18d2b9855194737b9ffb04c212580745a4b7083d2d568ee053ac95bcce28b3e06a555dc5774f6e0cc3e34c3d37a"
    $a4="745c22ae2124abbb3f9c5728f558a6459d9d44e9f0323f0afa476ce00550ee8de2d4da7d7e696ed91f1e426e113f21bc"
    $a5="b631fb6c0c99a65c097c71a142923677fc223777c71a2d078a12dc302b90503b43ad560198317e740ab63062c1c3bdb5"
    $a6="c9106418b7268ae6d2b144fa2c9717db01f0ee711f2cf9ce5ebad193a0db994e58e0c3a03c5863db47c332eb8523c4bc"
    $a7="2fb69b2d385e7196ba91de9a3e7e742ba3bbc8f6222ffbb82d1fb8fadcc958fb407e502e7f854274e0d5acbac94c5db5"
    $a8="bf6cb307ac8955eea5459612ff2a17e7808fff58482791402d7a98fac06b77916dab480bc313ac00e6f941db8c589f8c"
    $a9="bf6cb307ac8955eea5459612ff2a17e7808fff58482791402d7a98fac06b77916dab480bc313ac00e6f941db8c589f8c"
    $a10="2d44c39e6f6d3c8d4ff8e12ac88553ac84d6297ce2d8fc58d4f0dd5ab71926bf3d77c31648ab1c1e452558dfe2198658"
    $a11="60ce97a2c551bdee852a1c59d57c53cad060444d02a9381e78cd51a7647c0aa9927b6dd92a821af9ec50305453dacaad"
    $a12="a14f03985a6982cd8befc3f6036d49dbcd0c594914d7c9b07b1f477f44228ab921a9367b3375a99050582aa3100fbe2d"
    $a13="a14f03985a6982cd8befc3f6036d49dbcd0c594914d7c9b07b1f477f44228ab921a9367b3375a99050582aa3100fbe2d"
    $a14="6de70fa1acb5959f6a02c6c8585f296f69e13acd4f377a8494e87b3c6fa3bf9878cd4469793160ae605c3c1ef7c4ae3e"
    $a15="1625953ac77768ab52e08c1a0b33a7c43c072c83f0fa2fd2902a7f4cb01790a31f08ced9e603d389fccf61404b50c21d"
    $a16="7fb6fe26b59f3602d48700381502f16e11a967d2ef4f09f3fe034a3e5438973f503915987918115e4975bffd6a5201f5"
    $a17="7fb6fe26b59f3602d48700381502f16e11a967d2ef4f09f3fe034a3e5438973f503915987918115e4975bffd6a5201f5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}