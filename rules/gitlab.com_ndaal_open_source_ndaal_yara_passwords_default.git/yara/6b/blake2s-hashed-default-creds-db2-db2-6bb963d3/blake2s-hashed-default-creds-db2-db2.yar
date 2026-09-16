rule blake2s_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d59a7cc6209c3f94370d665a9dda648e474e83a83ba9a35d3b1bc55aaf69747"
    $a1="21fed00d06017af953781c6216a7c31bc1941935f6d0f4f12d3fd4966e9af5b7"
    $a2="65ef37a93e93616117afbc660a7933679c93c33bc8e7f8c09390723f1488546f"
    $a3="65ef37a93e93616117afbc660a7933679c93c33bc8e7f8c09390723f1488546f"
    $a4="028f7971807c550a57574a3f68c3389b3d2e8ef5dc3cd6ac5a41f3f5ad26779c"
    $a5="028f7971807c550a57574a3f68c3389b3d2e8ef5dc3cd6ac5a41f3f5ad26779c"
    $a6="edcd35326f7667f4ba1e0962b0e09c12d6d23398100664589fbb573d7defbf28"
    $a7="edcd35326f7667f4ba1e0962b0e09c12d6d23398100664589fbb573d7defbf28"
    $a8="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a9="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a10="52e5c4fe9968a568e3c91e6dfbd5a9587a5acc4a2d66d4dd574f0dead1ec7e81"
    $a11="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a12="32f1261f54b28d886cae4a15359166354b62168b5d0ced4b1207773c8d99c3b1"
    $a13="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
    $a14="837be7670986f6f8f4c4bae281b23e9538665da5a90be1f1a9bce75fd8c12a5a"
    $a15="b2d9bad1e76a19dcace226ae5d75d154dcdaf9b971b0dd441ab2eac44af68dcd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}