rule sha512_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a2="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="15e11ab0562ee203c7b73c10f792f1364623de4d2a18663c53e9e20cc11b001f3990ab2f81fdd0a8ce2c6a8b81733e61a32a89bbf55d2299369409bb0b8ce66e"
    $a5="acd79785b2922bfb3ce1068241c2106b5617ae10a6ce81cc2708ee6efd864cab04f86c54ea2f5345a45eb1dd1009b64addd9df4a083423de3c96df22f0b9ef0f"
    $a6="15e11ab0562ee203c7b73c10f792f1364623de4d2a18663c53e9e20cc11b001f3990ab2f81fdd0a8ce2c6a8b81733e61a32a89bbf55d2299369409bb0b8ce66e"
    $a7="6c94dc42777c943ce60d56c6fd851c51dfb96e177484706afbc50106b10bd297592f6d91701ec6f35da94636e6504e4aa889a796919b2dad10d987167f55a48f"
    $a8="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a9="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a10="da3f1c38b3ce6f87c35eb5b1e48e81e0781d5c286d1cb8c84601fcbc7fbd7c117979162f62d33eead86a1d6bb7f46459cc0c97b1e67acba8afb8fccef650ba02"
    $a11="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a12="d740d2d96e374cda55b6b1d055fb7047204aa2844615665e6764d28e6dcb79eaa71aa1a5a46a29d7ee3fd96c25bd1463df17ba64f6322d12e9baa77e0cf65c8d"
    $a13="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}