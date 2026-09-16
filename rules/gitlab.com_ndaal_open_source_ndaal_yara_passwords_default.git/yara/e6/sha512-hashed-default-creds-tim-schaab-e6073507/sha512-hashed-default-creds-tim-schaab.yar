rule sha512_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10c1a3be7b993eee6463dd03e83987f5c160af6552107bc53623426f3eb07e128b3cdd4865df74c506338e9fbd2de141857cc72b2cabb4eb315b3fb3d7d35af1"
    $a1="7681d198af9976f4b4b73ceb3bc7cdb4b5b7ae1da6803056916a5551514ad951382959fa57d7df3d8672fe8252853cc62809b338900bb3167b8501fd48a67f89"
condition:
    ($a0 and $a1)
}