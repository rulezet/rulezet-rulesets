rule blake2b_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="24a495dbd2edaad8c2812b1a5642227033b765ae9a63e7418b771f7abde2511df6d269b4c242a23f8b74835176aa07a2b8b225e2604206796e8cf237387a8930"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}