rule sha512_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a3="45cb609b65c72bcd4b04bb464b4e8f607a494b266b875fc3dde1486c1c5353cf2c65d98b34cb2433b9a1e4c22dc73b257b8217a182a9185d6da0766fa9cebb93"
    $a4="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}