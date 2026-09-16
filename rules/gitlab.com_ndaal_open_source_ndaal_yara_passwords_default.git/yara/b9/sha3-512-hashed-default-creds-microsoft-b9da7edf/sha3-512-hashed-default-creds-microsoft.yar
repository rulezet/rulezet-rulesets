rule sha3_512_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a1="5c84b826ae76b96ed9e9e41fe5788a16adc3cb185483b6d4008f9ddcb14a050e753ee2ad82433cea8a30dcf286418a4bfed6473b378ca0cfff3351ad7c433ba4"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a5="3b7defece3923499d88cca58e00c953fff15b87eb865fb82a5a44fd952efae8b7d0b82b53e380d941ae357e4e5d0a52069dd0d78f585009ee13cb074ba50c78d"
    $a6="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a7="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a8="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a9="90f2e09d2bbcaec0bf162a060461aa3f49647fec9cd87f0df9ea028e723ce3723fd47026b152f9fadf7af211cec81c285b8223199bce57ceb7aeafa60752a100"
    $a10="c567ae1d0f91e297efac5db0f1e4a62bbd0d56f5320ed11026dd6139676bf2853879e79b910de9677f1fc04648cdc330a98a655737e988c84885355553ec2d8e"
    $a11="c567ae1d0f91e297efac5db0f1e4a62bbd0d56f5320ed11026dd6139676bf2853879e79b910de9677f1fc04648cdc330a98a655737e988c84885355553ec2d8e"
    $a12="22e4ff124422f8de091bee72e2ec8c637ba473a4ee52bb7111eb4d2de258f41572debee13be0304c297baf04beed302f9579c9b417b4240c287c74551796f52c"
    $a13="2ad63f903f67c567ad52883679de1fa02a3affafef58cde990c4da8f2cd87e920664fa0563879a4a64e8a8373396c3a7b0151ae0d083b682c6089a3e1c57b95b"
    $a14="5232a44326f1d6742587f77adca5b26be8dfe0dc334d1e14e8a75af5d0127c4405c1fe88f6183672493cb088be76fcb1e2cd04c58e6e66e1cec50c3b94cda7d8"
    $a15="5232a44326f1d6742587f77adca5b26be8dfe0dc334d1e14e8a75af5d0127c4405c1fe88f6183672493cb088be76fcb1e2cd04c58e6e66e1cec50c3b94cda7d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}