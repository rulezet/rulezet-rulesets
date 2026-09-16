rule sha3_512_hashed_default_creds_mike_peters
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mike_peters."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed311dffbb1ef20e418c9e91f48d6125ab4fa57e35c0ee20168bb4840a3c7d883793d626bc95511d6e7be5f3fd2d5a9b00243aabb0fd6cf3f8cf38fda8ac2e0f"
    $a1="0851d1eb63a96ad11fcc22d278b7183321d7817c0ed56e9b13b417a17bd4db4aa93f54d3949db257b07c74a664d165920d50b37cac4edcd31607f8c5fe38b4d8"
condition:
    ($a0 and $a1)
}