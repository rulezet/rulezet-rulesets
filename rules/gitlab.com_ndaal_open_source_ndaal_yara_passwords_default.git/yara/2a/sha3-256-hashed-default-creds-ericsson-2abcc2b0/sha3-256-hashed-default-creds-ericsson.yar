rule sha3_256_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a1="4d235e963851a33d292c78aeee20bb9c80f4be6ee31b2e38fd8f77297e30bf13"
    $a2="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="1782ca260b116c2360821078875e766e03ba1cdb547381416e2fabe1c495804b"
    $a5="5e6196ecb5f28fa44aaf3d2fb0fbc1fdd0c6cd303603bdbb5abfa3e34a9755a5"
    $a6="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
    $a7="c09d48b3d5671f93f6bbe8bb21f15e52ab4e3cd035574200694c965b64f75998"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}