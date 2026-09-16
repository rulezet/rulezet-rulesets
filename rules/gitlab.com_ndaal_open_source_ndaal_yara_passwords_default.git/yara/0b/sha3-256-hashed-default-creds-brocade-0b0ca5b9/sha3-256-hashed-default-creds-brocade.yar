rule sha3_256_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="deca0f27c3ed4d9de7e471f4b18c97b2b022dc152f281066c9f7325eae9dc0d0"
    $a1="d46b2ac485394ab8ef0a0f0fd4fe1cf11188dac9fc6fb4672f79cf9ca3f6385e"
    $a2="20e96233e6a11d6ffd57bfbe41c79d90670057253d905ae1cd2e54c18aa70cdf"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a7="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a8="695ea791eab813ea9523c2d3d800f447146366ce0d2e0aa8fbdecab6fe74654a"
    $a9="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a10="7560a7f3f0cf0e66b1923d4f45e89d526af2b32907f5fca081b23c5f064572ee"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="7661da70cefe6c7c07b429f7f482004eb90aee28b08835ed0c0ae18fd341e064"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}