rule sha512_hashed_default_creds_textportal
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for textportal."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a1="a7bffd16a550861887a18b68a1e7db9c25753eb3404b76774361eef723bb86492fa48f79e5128ecf781317b8cc44e24581dee2113f6cd08404e18c20a2cc72c3"
    $a2="3627909a29c31381a071ec27f7c9ca97726182aed29a7ddd2e54353322cfb30abb9e3a6df2ac2c20fe23436311d678564d0c8d305930575f60e2d3d048184d79"
    $a3="f021ab9426341d1bc264e5917e21ec81d1230e27106878323ab287fdd222c4ab10605b14982b680082f6e94a320536304c8abd225d7703467e2140bf5959e929"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}