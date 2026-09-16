rule sha384_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
    $a1="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
    $a2="fdfa94fe76ee9313e9b863293d5bab58af1d03e4cbe2122f197117d5b89c77fbb03a675daa81b0277f3c69446b618154"
    $a3="d2f70e23ca4fab9e7c69373276a1a7b37af241e97b15af7af61584c9e5b0538750efaa8deeb58e783a7ca18c88f249dd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}