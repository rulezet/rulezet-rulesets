rule sha512_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9db4397def3c048dcf39880258c8cfa459470a21d910dcf83000db47e0b21f263e6a2f3c3b655d01540d4667db3ec3a189166890bb1a3d5d0a3fe174b89dbc5c"
    $a1="9db4397def3c048dcf39880258c8cfa459470a21d910dcf83000db47e0b21f263e6a2f3c3b655d01540d4667db3ec3a189166890bb1a3d5d0a3fe174b89dbc5c"
    $a2="62884f1502a3ab60eb54dec90857eb9d6eeece3fe1367808eb884809786975b497c1c761f410beb09aaea0431ee8b8399c787395bf22211aa8cdfb21ad7f142c"
    $a3="62884f1502a3ab60eb54dec90857eb9d6eeece3fe1367808eb884809786975b497c1c761f410beb09aaea0431ee8b8399c787395bf22211aa8cdfb21ad7f142c"
    $a4="f29e81adee90f4c99afd29094593164a88f122f6f20ec58d06ad1c18a9c4a97410b267cf77a418da968c45c1283d77111af43a3b53884ff60edeb9bc1ca2cef8"
    $a5="f29e81adee90f4c99afd29094593164a88f122f6f20ec58d06ad1c18a9c4a97410b267cf77a418da968c45c1283d77111af43a3b53884ff60edeb9bc1ca2cef8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}