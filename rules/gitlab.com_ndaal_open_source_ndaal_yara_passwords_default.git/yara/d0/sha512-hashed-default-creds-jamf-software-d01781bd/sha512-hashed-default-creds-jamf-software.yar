rule sha512_hashed_default_creds_jamf_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jamf_software."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="263eb25c81a54f5b51a04e457ec11140f8623ec66fdb27fa6bb62c43c726f78811b5198e288466d730ccbced6cd608b9cbcd651e836bc606752dc8da41bffed1"
    $a1="5355c850cd7d3903d5bff20508757481d54c15e5828691ee8e8734f3df65634db08671495dbfd286564a5b072cd039383493ea1d1db3e32f0d8731e6dc284dc8"
condition:
    ($a0 and $a1)
}