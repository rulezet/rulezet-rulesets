rule sha384_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7ef8a755d780d5045094eb18c000e55ede5cc3fe04aefc244e4afab1c65356e2eefb0038d1bb2a71be9363b6c5ecb38"
    $a1="f7ef8a755d780d5045094eb18c000e55ede5cc3fe04aefc244e4afab1c65356e2eefb0038d1bb2a71be9363b6c5ecb38"
    $a2="ca2391f24162e854b3998ec1933192a772e7d2314c782d7549061192c72c5391fdfec15f776bd43aef2243796cee4d40"
    $a3="ca2391f24162e854b3998ec1933192a772e7d2314c782d7549061192c72c5391fdfec15f776bd43aef2243796cee4d40"
    $a4="24132c317f30eb4826be0607b62288aed409f02faa89ac1d00c15b38af25fe62b33aea44e502f59a5ac52c04ae2b36e2"
    $a5="24132c317f30eb4826be0607b62288aed409f02faa89ac1d00c15b38af25fe62b33aea44e502f59a5ac52c04ae2b36e2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}