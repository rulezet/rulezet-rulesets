rule blake2b_hashed_default_creds_polycom_vvx_500_phone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom_vvx_500_phone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98186e8212d82bfdcf950da3075d0bf7caaf55e9f52155beb6c9230559d2970a90f11ba4c4b486a2cafbb51f3c8fbe9bd4b386eb13ad03dcc974c22a30bdfd05"
    $a1="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a2="e64cb91c7c1819bdcda4dca47a2aae98e737df75ddb0287083229dc0695064616df676a0c95ae55109fe0a27ba9dee79ea9a5c9d90cceb0cf8ae80b4f61ab4a3"
    $a3="ffbd009a16b4af1cdc094f01aa869986899a938bb64792a133952bee291df72556d2e2e0f65961cf92a5dd137929df475303e58cb4525b9fd287387931057159"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}