rule sha512_hashed_default_creds_hitron_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="992e30749dae77c01b27decda544a7563d1289a7e62b3bef4b3552242b99b7f49dc039d4cfda042ae23952c1b774bb62d63cb143f34fad8e4840c93004538706"
    $a3="c321219a94514ee52fef6a22aaea4181d1c33b47e419b28718f650746bb1be7929b33e27bebc127d52b70292c5fa3fdcfc2f0129dc43650ee939e81fa5d45e7b"
    $a4="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a5="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}