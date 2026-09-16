rule sha512_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b276d2d9f7ec787739c9b13dcaa2bdd79faca1166914854333c76609350a5005d413666dfe67427d7d345c070ad93e367bb670f2056aaa025114b9f29444bb81"
    $a1="de91078a5b1eb16864d1db7baffa09ab367e6ac301fa61a484dfd7095def57de8bedfa2ba415f59d7e76753c807d0fc5b0e8963d1fd1992b6936ba9383c4975e"
condition:
    ($a0 and $a1)
}