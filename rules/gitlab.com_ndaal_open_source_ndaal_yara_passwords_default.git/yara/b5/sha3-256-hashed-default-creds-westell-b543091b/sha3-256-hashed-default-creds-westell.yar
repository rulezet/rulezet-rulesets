rule sha3_256_hashed_default_creds_westell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for westell."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8eb6be7da27a445473bc50d1bbf60d91e06b1332156ffdd252d87270bf351bf"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="08ee5ef22b5b1f6c39637bd0dd817ad86a1d978a056942ac073067a483f3e02b"
    $a3="9361e667282efe20304db27b6f4008226dc548073663a94c317c1cde7d89a102"
    $a4="898ed4288a93ce276d052a269c3a3176b26bccfbcfbe93289467fa7aec6650bd"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}