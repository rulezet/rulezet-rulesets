rule sha256_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2de8a89303d3ff0ac243ddbc8ec7926c19d3494a986e110b82e91e0671f4d803"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="48144a5881f37fa0108194419df0de6d46f5bf1e1b60c2706d3377a02db4a000"
    $a3="ad961909dbf6279c4d8a45b8dabd9a5307b02478e01381bd4e7db0412b25e9e8"
    $a4="b681d7a7ae7d77e42f2775527507bf8767d8b028c75e8b87cc8084d73d43c115"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a6="744e3df6af2898cb4888fb7567f4e81396c55ca0859670c293b0676c9ce9fd4a"
    $a7="93f1800279c7acd3e7b55b984f5a9c4ca16a35c54e1d96649602f7d9aafe157b"
    $a8="1fc7a460ffbc5d34af0b6b7fd57f3d55ed8551313c6f1be4f77c7db3eff1e89f"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="98cdf893ea9d6e34066b434353c4243e63e952ca11df6ed2d15d0f5ca78d93dd"
    $a13="fed4c5499a7d18e4054ab175eb87b19f39cb102b1d72adcd471052b7b9e5fe45"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}