rule blake2b_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6bdfea23f165ff59b09e6fb66b3dffeb00191604c2b4dc66d4c19ad2cf95a22fd09de06c5824360bcdd3546f1480b6815a83cc325225ce16277108adefe96a99"
    $a1="b94e69a3e35abd67287cfe7ce14365a291a60ba853349a36c06fdcae2acb5381fde7464165620ed5deb1ee51d5d04111ef5f417764a44204953ba02bbdd4675c"
    $a2="c975a3db7aee7e1177ce9a4889821ac43b33eff458b0bbb1a6986bff776d286f9934f9d23eadbbec4991d05a131142c2586e9051a4b200ddfd0bf028d1571507"
    $a3="f100c65b0d6bcfedac6fba6625e7705217433b4759a70287da5a5153bbeb5c23df492b60360d6d5b3efb5faeda2f626836b6c76d89d7dc7ca902aad40ae3abeb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}