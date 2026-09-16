rule sha512_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6eb96a4ad1a6a0f4a9c692b2f0d9beaf6ca09d3a954ec2c191473a6c91db43a2038bc7dc145ef6fde73f4c1d2f6c778d467f142b03f80972981107316cd89202"
    $a1="a5f5fe6fcc9860296c14a22f0a4cb48348c3953edbe94ed4941d10e6615ffee9736c8ad3a6c64b32b9c794edec9effc275f45be607852a28fd88dd8e67db12ec"
    $a2="fca6e7467e75955a8d89235a5aea84c78c247bf60104160a53fa840e9d53bb9ad88a41d1b16e3bbc06d593b70c4e3ea255d160f79cbe7f95bb80ac507ee931ad"
    $a3="a5f5fe6fcc9860296c14a22f0a4cb48348c3953edbe94ed4941d10e6615ffee9736c8ad3a6c64b32b9c794edec9effc275f45be607852a28fd88dd8e67db12ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}