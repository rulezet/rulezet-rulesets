rule sha3_512_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca94cae11a0d00fd99fab03ef31115b68806b1efa1f19cdc78ef56c44f7458bb62560a684e481efa407ff3085af74de657eead373794822a3950b76b756652c"
    $a1="71ca8e625d2845307565ac9bdb13b4d58a537bb16f16f4d2e6983d30b43cd77e707cb2f1fc3e92bcca1d00684e21f440e822bd3f43ef90bc142f08a891bcc110"
condition:
    ($a0 and $a1)
}