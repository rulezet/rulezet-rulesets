rule sha512_hashed_default_creds_mysql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mysql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="fc063b5c2ad541510b5e178a237d975dd4bbc74acf10f03d1a1fd901be6581945d53da7ce4b42c6baa0499015d64689cf5d578f37c0106ed7c9d10564869b8b6"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="77e53647dddbeb1bc6abe20ed13a846c5cda2b29ed69596564acf090e31f7e0449ffd4ae5704dee6e7f925c5b856dbbbc8248e4c1c03d47dbff1d7c4f327193e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}