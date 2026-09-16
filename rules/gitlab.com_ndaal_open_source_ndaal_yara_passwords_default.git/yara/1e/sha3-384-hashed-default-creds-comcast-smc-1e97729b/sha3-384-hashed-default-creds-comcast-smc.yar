rule sha3_384_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4beb0cb4b86e5fe2ae0992939d94cae2659133a7fb645e875999c5753286fdae94717a16b53fbd5af6c99011925ea61c"
    $a1="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
    $a2="1d243ea48da2020cde4f09bd8d38a01876f099d53bacb37cffed21309dd399c9cd57a4dfa671c06ab2627c6eb5e23f99"
    $a3="768e9f484407d2d3f91ef8ede60886837c48cac9409422b9ac17fb296fe5bcbee2fd72215b97f6b8edbe0c51b3c090eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}