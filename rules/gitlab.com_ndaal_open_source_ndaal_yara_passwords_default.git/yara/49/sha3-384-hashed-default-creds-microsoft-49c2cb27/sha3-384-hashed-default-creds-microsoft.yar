rule sha3_384_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a1="81716125a9b6e542bd0736fa4b04330f7fc1ef64eb1390428c7cfd7ddfad29dcaefe8b0bf3615fbdb0570be99b91c926"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a5="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
    $a6="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a7="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a8="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a9="6d2bddea82451f8471ec7642ce69af08a2be6845ab02b2d5094fd89640037515a544044c7fbe733a7d26d6758892e60a"
    $a10="5ae3f7721d1cb33db42fad05994b030c8623d75b247f659554457887d93c3f7d05fcd9c1060fff397709331233e7d729"
    $a11="5ae3f7721d1cb33db42fad05994b030c8623d75b247f659554457887d93c3f7d05fcd9c1060fff397709331233e7d729"
    $a12="7cca4bbb98ea5cb8e55c6b10b33d2d07fabeebd47102dbac0c02e5f7fe0cba8d46c54c93da1aecdc932319bf1b55dceb"
    $a13="a0e05ee90a719226b05e3439b3b70d9f1d1c36832f075aff5bf6f1dc1232de34277454dd278c58c05eaaebc589600f6b"
    $a14="e1176aaee5357fe006f136949a6529e05074bad4caff8cc89bafba2c6eb5637089f87f4eb21861d473e104d26135836e"
    $a15="e1176aaee5357fe006f136949a6529e05074bad4caff8cc89bafba2c6eb5637089f87f4eb21861d473e104d26135836e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}