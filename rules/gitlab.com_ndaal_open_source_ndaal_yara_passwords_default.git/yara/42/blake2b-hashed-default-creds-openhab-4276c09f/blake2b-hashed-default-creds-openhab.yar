rule blake2b_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4835672288b60144bebae640dbd5d0eee46011af4c571f3dc6119c772bfdd53b074276415521b1a3074f9a6ff68d0d5e76203fb52cec9ecb3e9bfa07357232d0"
    $a1="4835672288b60144bebae640dbd5d0eee46011af4c571f3dc6119c772bfdd53b074276415521b1a3074f9a6ff68d0d5e76203fb52cec9ecb3e9bfa07357232d0"
    $a2="30c1959c2f08f4859d7d6d045b8da1766a547a733ba7c791c2e16c75d94f8f28abf3d7f352b3531c73dd60aea52d03af2465177c5b6538d023fa49c7e984ad2f"
    $a3="1b9b1f01f5724f145ffcb78bf9b39fb6532e73d2d71c8efde4678f81293ad4201cab737fdd9882648b8446180c5ae8e1f650d31bffb006c2f2c16f078090e0fd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}