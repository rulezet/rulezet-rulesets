rule sha3_512_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
    $a1="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
    $a2="93768e12f9eb8326e1ee8d648c3552f24bc26b478e34eb1078c69027b8eb66c436c6af2b79c940d236bdf3a2dc6d1290a6728c62928096fab7a6c8d4af729aff"
    $a3="4333fe9f6a43d1e0df1a61ee918e0a17ce45ecac31dce0ce4de2fec1f63d33e77fae1a6c95bef0803b986c67bb39d062bb25c25320c5a8c8f26f62db307ebbf1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}