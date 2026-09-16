rule blake2b_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bdf217367281ef6f820983eafa704c7fd9fcf1b20e6ce9745da5c976af399702c582a2a9247c6254672d148921e89d06e8b605a5b4c0c3fd74e960880c69297"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="31a330e8c8e72bbafd399ac5f50823c0682a5d830acbbe8df65bda0e7a93178e71604d50a9698af12175a35ba66e74dc5749d7991bdbaa638fc9518d3f3f4b12"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="dfa9daa408bc2317afad1086df4f602fff9a34309c2202dc6ebff703d85fedfb9ac0f1a35da6c3589dcc9730145934675694f66aa7a42f3714d78860c908275c"
    $a5="8d2f4f0bac20160beccfa32131beeb745b19fa24352e74356659edf6e463847b91130101ef25bf20d2cd8bb46a5b3558f5fe28361c15ca6e6513160d569c9592"
    $a6="b540ea01ced69e6e6159f992e3ed9c30b7a65f08f2f031ee6147c2b6395762004f79c137503167324ce307f412f483348f6273c1c33a8b42f4fbbd856d355d67"
    $a7="ef2fd09f1a0711ffb157269b5f22c433a85a2f3396d8d9348ad9564ea7a6bd425026558c84725e288b9eea12002305558cd95e61fe7a198d1bb69df986c1b3d3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}