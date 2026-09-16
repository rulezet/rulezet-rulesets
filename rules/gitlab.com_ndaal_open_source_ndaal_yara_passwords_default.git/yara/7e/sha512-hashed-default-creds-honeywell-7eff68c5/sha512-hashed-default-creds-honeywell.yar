rule sha512_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a1="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a2="4dbb441272177a8af5add51ae4c7012225d5f02945aa58c0837c93f8fbdabd5661c0dec1de578665accf19516f1b13eac440e5c72b73b4252e807d1b391a4049"
    $a3="8d1a276efbb3cdfb4aa060818066c78417608fe9f457502388d688335de754f488731f201960849411c68a01c0c01827fff2d9d14fe868e3e8157e8c3ef18caa"
    $a4="4705392774c804670fd1e7e6ee6842456525d6b6ef473d97f1c0db8d70339dcad36159883e0c2554172d0af36e4db63c8259298c69ca87edfb09186ac35528f9"
    $a5="c185ffa1290eb1d9ff7b87cb5fa6b3d0ef1f94808b8cf42e86655052d182128d5609f6e940ef972daa1bde28d9885822ca8e3331a529a270ca6278e93e233f8a"
    $a6="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a7="cc5ec2b61fbbdd18d85dd14ab60db397b21b5548999a6afd3ce9557b19c300494a5fd29987e03a6f06677c209b88de47684388de8250671cdd778799eecd018a"
    $a8="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
    $a9="ec80f916d6bb87fad058cfd70adb9381c71cac73b6bf61a50a9bd165835deaf5114f6b6c2a8d8208673cff482f6ed9997f69baa6fe4b391ff4ec15bf31850abc"
    $a10="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}