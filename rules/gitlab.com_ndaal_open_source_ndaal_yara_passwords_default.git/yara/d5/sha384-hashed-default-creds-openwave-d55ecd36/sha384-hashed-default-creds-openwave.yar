rule sha384_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4002f99dfcc7297be64076e6a204c24c45e26ff29df305ced73e66730c297bbd503c417e1022f914f36a7c761d885799"
    $a1="249585b6e8a1b8a22548a6c73507b3310fbe648e8dc92c8e725d7fdcec4ccee930f2df5c5569fec07a06dd8943b4b779"
    $a2="ff428ec7d2ee6edea31648f7ab027313a465dc192539909745999815b94fdcbf246a5be48a0a661cd235a1fe01ea2ecf"
    $a3="8a7c455d373266f5528ca765beadf67b8cd9df1f8c3fcfb5fdbd7541d0a4a389eb39360fb6439f474cf0e538101df97b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}