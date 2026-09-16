rule sha512_hashed_default_creds_acie_securite
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acie_securite."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
    $a2="f5098252f9c3e4cd9b48d5066f9897f9aa8ca30e48a0bad04288525a994d07603a98f73c9f2ed9a88bcce8e106ccf738b7ef09c1346ea012694a1e164348b0bc"
    $a3="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
    $a4="8d61523a6c320d907be2631cfc43a87caf218ab667ae1e121d48f73360561af81afa99f316833f36ba01d57aa21a446a9cd8726304f4860e368114dbbcebec60"
    $a5="c9e3459f126bb7a7e1e1f2985f06fce35d3bfd991577a66828bc3531d34a259c4016fdf15d2318f8928fe9030192e105c89c5ecbf982dab885ab22e6bc52a8b6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}