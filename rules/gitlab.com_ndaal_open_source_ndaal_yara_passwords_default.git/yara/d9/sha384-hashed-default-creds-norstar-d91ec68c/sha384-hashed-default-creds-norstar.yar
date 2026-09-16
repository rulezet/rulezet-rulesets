rule sha384_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="120197f4c2c07b870b9689e297bb28f03f722dcc7d003bb0dac3098a98b6207cc54e6183b147811bdc025a85627d94d6"
    $a1="5b0b72d2f752ea9de3e4d56d16fb629d77657009a084b865f6730f283df9ea23641c53dde4bdfad42868a32bc645668e"
    $a2="0d2d1c3c3f720ed23fdc8d9f56e82167652c32ee5fc72d9929d59abb25679f7457c5e7a4dcdda50b921125a4511e74f5"
    $a3="fcb772663974e213b9c43e4e93c866a9d337981bca733c296d1b316c71a633ca42f39fc1c8656e0da7f32484c4b3d6f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}