rule sha3_256_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="797275582132afc384a99b71ab73b4490f7c96a838c8ad9db9521d1cdca8d537"
    $a1="797275582132afc384a99b71ab73b4490f7c96a838c8ad9db9521d1cdca8d537"
    $a2="68d1618215a76880a25b217f7d2db83f1af5f57aef6ae5ffe004d25f36d7828f"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="a214f7312073b63bf1c183534e979b18533771ab290e105043b898942702a995"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}