rule blake2b_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a00776d99560ad680b1d3a12a848b54d0238559ae1264af9a8aceba445af6a3593c457f684ab23f9ef18a09bfd6f33b894f51775e169a6832e816b121e5cb34f"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="11ece2058bc1d9b592b585b11d018f73067086e1e8b4d53c4cb6871bb9ba5c5673bca32a323b8d09819a1b9c35014610a0c71ac25f2e4f72c5e0db9fe2973fae"
    $a3="d5c6d67da69608b42fdac3fb407f209c71efa344d77e446f12e8b73bae873e8837e8eb03b30b29f4ac27a99ec080be30cf8e5da6423942a22f51dea3f0f196b4"
    $a4="fa3a147cd2a2861057edc69183e7171e0dfbbd76ecda9875c201c546c378e9ecf75d0cb13b22536540061ce0093cc5dbb08720e3f64ecc5991bdd2a624afa072"
    $a5="fe03ff34c8b135660afc2d240ba444ee1305182be6e0da51ff1343408b646da7401ea8c6ea4b87ffd04ae03c687eed6f6d078b35c9272c77a50c383ac8a8931f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}