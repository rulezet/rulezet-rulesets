rule sha512_hashed_default_creds_network_associates
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for network_associates."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89f5654c35384d63975995b021eff8abe1f5e17fe6e7e87c15ccb316954ece3bb7738648781b2122021f3adeafc5369fe0f5d516f1fdedce2a88327c3dd09064"
    $a1="cf3ed851c2bca5e3f7c807c68e5487d8cb54b450d901ff2ccd545abdabddb3f1e7da1b743612f08952cefeec1e79905057add52ff71cb08a5d4c8778921d8957"
    $a2="c0ae3eac8a741ba529d5302c3c897d31b6c4cc78daf72e57fb5d9bcb0a7860bed93d0406258f4341a4a38b7f11393ebc4e77550180cb1aa993565c33b8673fa7"
    $a3="376217211b17c39bc42ab92e485775210533681ad7afbabb0600390862ba6e9dc2d41e9fdc49a00fe027752dc01237268069cb6f66970e5fdb8e0ed14847c3df"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}