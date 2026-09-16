rule sha3_256_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="697cb364e493775b2f9707298f6c286ffb85d86ec3f5ec01328002253f1c32b9"
    $a1="697cb364e493775b2f9707298f6c286ffb85d86ec3f5ec01328002253f1c32b9"
    $a2="6e19fb7432b303886d004f79859abb79f1ae180ce62c8ba79a4845ab037258a7"
    $a3="0af52ca89f39fb69499cff6948dc69129c3d6d41d0c0c9beebe74e951e1acb34"
    $a4="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a5="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a6="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
    $a7="e239de1942d79eb9759b60e6b7e98e9cd17694616af0b38c8816b4ceba6a9b77"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}