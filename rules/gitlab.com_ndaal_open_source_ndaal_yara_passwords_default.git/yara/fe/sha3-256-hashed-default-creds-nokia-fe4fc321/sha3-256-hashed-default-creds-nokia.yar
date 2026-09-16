rule sha3_256_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a1="bdaf93e1d2634a74791d37c11904211325d89d7dcf2c6231960f8ae15d1c3401"
    $a2="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a3="86cbdabeba46c2f05e460f7183d20a09cb01c354fcb81d29ab54773e4c7cd490"
    $a4="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a5="b0c487aac068df482bf0a6ca161ac7dde146730324ac52c23dc429975a64fc6e"
    $a6="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a7="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a8="7f2ca0d7e8d2e1e283fc1bb42b26da97da44ac170909d2fd831eeb1e0c5fa49f"
    $a9="f51812338f1d3993ea2fc873e24a049420606a22e8d24f2a9f2aa4687d98f0a3"
    $a10="eb03687b75749f50dc368946860642f928e14e00aa80ff438ed0105f3a608bcd"
    $a11="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a12="50ae02b46526f6ce0bedcd33b475840f27e148b312e8089dc2dfbc10ddca960b"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    $a15="be2f847879f73004a0da3c8dec8efd24d8671a15d4f67d51a9782f8c4394abd7"
    $a16="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
    $a17="4e0e9f5fa7bb1a8778118cdc604dd98c00f29f34be0c54227e7c26e814152f32"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}