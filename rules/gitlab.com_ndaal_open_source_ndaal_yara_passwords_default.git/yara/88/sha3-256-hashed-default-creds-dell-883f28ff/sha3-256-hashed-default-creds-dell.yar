rule sha3_256_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbe30e1fb5a433233667618f4f1fbceb8f77b14ab2823efe3ab23c356662f013"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="02d3a79fd50f582d66bc26eeb332a4b1583c4a79414aa9eafbc8ba2f450df674"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="f278c670e03e528f8992c36d3df37bc9ff50e7c182f3b9550acc374ebbc3b6fc"
    $a9="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a10="7b01874fbdacafa045b51b9cd998c4840c3c7746b9f5343723dcfde1a0ad979c"
    $a11="f325e8a45689e7c93a6a5540c3ab2ce6feaf763a3166b7dd3fd25cf7c6c6c92c"
    $a12="e787eeef9f29be13838111ba1c1267d6ed9f64d2ee862b863d16c32adff482bf"
    $a13="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a14="ff69d6c044543a4c14088b32b7acf489501324dcd38342347f855cff8fd6e9d5"
    $a15="f88ca7c8ebc412c940cc28cdb8ff244ef3b94421ef955241d1f6f54fa6557814"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}