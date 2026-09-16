rule blake2b_hashed_default_creds_zenitel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zenitel."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c93919d670505fb3e4671078dad31a8c878dd49d9babc90653d130630f5a0e9654c0bce24459f8fce97533922e0c45e4d6f4c558c25db5abf70677df4fa28181"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="f8216a868585a56bc4dede1138e491e35dadb1efb2c09ea9879b7ce42eabd5edcd57eab030f9d8e817ad44db261f3c3365357a1b9eb4727b55c6abc39bf488a7"
    $a3="c389a08ca48765ed7f0303e1823e4c20adf79b08368733b97fcb20b7c23d41e7487f826b4ee7c9c66b8e9d5ea50021271add19e347bfbfe0d5c6a053cf848589"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}