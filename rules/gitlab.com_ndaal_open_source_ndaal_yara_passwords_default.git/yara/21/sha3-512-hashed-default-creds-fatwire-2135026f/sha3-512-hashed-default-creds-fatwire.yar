rule sha3_512_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac02398209b4a3469f8fdc150274d063550ad00ccab171e672f08794cce906920727fe75b9515d632d089cf7e3aeea4fd9a9dcb9ec9f869085296d147dc5a4cc"
    $a1="ac02398209b4a3469f8fdc150274d063550ad00ccab171e672f08794cce906920727fe75b9515d632d089cf7e3aeea4fd9a9dcb9ec9f869085296d147dc5a4cc"
    $a2="5821cddef17fb944885892b421963507af4ab9bc8edb77b29252002a04b44f3a74a90b0786fbbf23b9a18c80972ff549a6ec372998c26388075481f2d53dfd26"
    $a3="7a4827493d45a64c6a2f0bbb4713cce02f0abb1a0429d021c3ae6c53798fdeeb91245cdf51f37da0635f615fad9ff6401649c180afd908ef1751101fc13a66f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}