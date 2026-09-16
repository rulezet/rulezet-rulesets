rule sha3_512_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94821b0ea102d097e2c7b4715ebaf2e7423eba8814a537dfcad5c9cfac09d0d8be5be1af0c317f44295ff92abb2a8f89e5c25c820a82a8dc19bfcc299ec6a24a"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="fa25fa9134708d672c9c55622800621c70f72878b3d1acf1ec2d8351c01792957b4db4ed2b7b00a3dc44510bc0135629eddfa130d97572ca0dd1951b35d76060"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a5="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a6="ede1629e063689808f7abb5355aff8599039f1e4854eaac0a351aa7f2bc70417c393af8bd2db0d77d827d421ca18f2c4b3800fc19ea8b4b94c35b294b864a168"
    $a7="7841bec97afc1fce68d833e1b37f7ac9a5acde407ce5ca14a4e481b61047aab194c7c2886599bb5c940158c8bdb8906557788dd0c172ee608049aa31543eedfc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}