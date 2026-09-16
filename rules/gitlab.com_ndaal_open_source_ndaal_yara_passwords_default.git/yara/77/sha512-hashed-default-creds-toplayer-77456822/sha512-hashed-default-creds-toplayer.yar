rule sha512_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfe22dcd5b3f9fb745c406374feb9a5af60fab038165539c7c44700928e075cf6d54cfb8fd3b0a16d0a25c7d68988a4f242da7e08429066197a7fd1c7bb38e54"
    $a1="8cb396a3bc1acf6ede3397050437ffcf4b18dc0a26b75e67d257be5431eed904151ac118e687f3fe42438794106136ca7047b6d2a2f271054a44528432184ded"
condition:
    ($a0 and $a1)
}