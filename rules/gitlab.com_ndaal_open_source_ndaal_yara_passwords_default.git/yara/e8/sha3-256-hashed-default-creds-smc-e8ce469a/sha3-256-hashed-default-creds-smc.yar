rule sha3_256_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a1="06930fbdce4d7fba6cc4c3bdc7f5c2d20bdfcfe9ee51364be81e119e70e6248b"
    $a2="0c251f4f9fb5fa97f7950461c2d2fcbf8c2aa4cd1d86319053f72e90a4a56af1"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="24af0329dd22bcdf3805f1fdd579b30681ebe2c4c0b89eceb528158b64cced67"
    $a7="67974796ed393c0edaca0023b3efd3d2f56130b13b5813354624c500cfd56b95"
    $a8="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="fee72e0c85e6f6c5d2fc4a6e18604cf2202563913f5995bf7984217f5680042e"
    $a11="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a12="8763b9749ecb7a87a023d92dd04a60cb7e3443f1cbb040a21145713ce9c70b24"
    $a13="81197174dc203f5440ff4e2abc106556e591648ac6fc30f50803d69e31911633"
    $a14="8b20283aa7cba959cdd356f03d0db09434fa9140a72caeac7677eac37992bcc5"
    $a15="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a16="82c3099b1c7c22250266ca625b7b6294387d3e1b462bdd0b51937032dce79c5a"
    $a17="2747cabbb481a433679f6dc8aae833dd1b64452778b97e2729bd3c54dede0886"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}