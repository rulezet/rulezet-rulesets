rule sha384_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aff4e02f6a5694606ac6480196ee6cad61d37bce6bca1009e8a2c64bd78f01675e2ccc86e7f15a9ca86bf53ee8771cba"
    $a1="924ee7b4065b25d8a933997d230d78e41a1d68fcbd709cc6573eaf96cd5f74e9199e45044d0f945f66bd18f77a6e54f3"
    $a2="fc628e4a904d3e0712eb453d27d05c26e32eed150ca2bc905dd622a49d96ab34d177a6d848112a83726e5f318c909bf8"
    $a3="b5ff757b5f6ca9c2e392275181751242b55b930d475a36d7b4119e61e6568151aa6224e3d4f5b1f5e51e9673bfe54c57"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}