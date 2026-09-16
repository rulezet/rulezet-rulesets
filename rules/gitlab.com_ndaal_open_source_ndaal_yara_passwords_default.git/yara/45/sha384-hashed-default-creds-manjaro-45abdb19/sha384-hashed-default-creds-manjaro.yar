rule sha384_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa3bae37672148acf5397a4f4badeb3177f54115d2db704b0853f9301510807e76a59f62213bcebb2d7e8ac89609e36b"
    $a1="8d1bf654dce97cbc88b017bebae635d094425323bfb418fd1182882f40741e8ac5b104f85d8af1fe26ae76eb4b991f7e"
    $a2="4aac17c66b16861a8c8d205adf61f2870bc67dd81459810f927fdc013813bc9467a9b43c535ab20ca357c9487ad1b23b"
    $a3="8d1bf654dce97cbc88b017bebae635d094425323bfb418fd1182882f40741e8ac5b104f85d8af1fe26ae76eb4b991f7e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}