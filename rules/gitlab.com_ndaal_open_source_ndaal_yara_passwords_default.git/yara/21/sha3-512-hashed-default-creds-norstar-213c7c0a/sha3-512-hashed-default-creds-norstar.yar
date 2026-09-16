rule sha3_512_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="babb1dccf9b88a18531c5cb76313766b91236b49c6af06028fc064f3ef3e94cd7a48c9197dc8807681c05facf69369491814abacb2705c30f59f87bb49aa2551"
    $a1="77a4ffcf3e7d6224ee81d1b7e58b0079ef220beac3337e7875e68773c5292a78d69c6628b201d1355cc6289ba576942375cbdb830a3bd7c10ab16ed85c133ea3"
    $a2="93d604ddc4176ed4d2ca5f8d94e3b50d4ea5905e297e4eb1ff334005c06c681c0da1b4924970993ebae42dc33556113b39f45db11020063615496d56b74fe53d"
    $a3="1b36c520879007679b5e74cf3323952a9d4d82d86f7678588a163ba7537084903a23911d2079412a21a04be3724d82dc27e83f81f349d488189f2272769c6808"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}