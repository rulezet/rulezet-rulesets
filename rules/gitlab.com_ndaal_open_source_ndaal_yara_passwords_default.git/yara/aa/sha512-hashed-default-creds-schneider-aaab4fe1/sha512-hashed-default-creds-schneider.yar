rule sha512_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcf346a597f65e994600a502e782283b7c2e9eb52b8f3fbe8f820d1db2ea75747d7d2ef308385241c6d9baefb61a4d60e596b80927759ebcb33893574969de5f"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="d6be2b194648b678e52086653488cd0278a21625307436e90cc00ec7e682464107b7c5447b1df3b981558c1d8a4dec11797c884d1c45500d25194ef64f45b46a"
    $a3="a3ac8332a9d99477413bfbd339c551305b4a5eb89ba7d3268c6be38ca1c0792e90f73503570149bc2ce5c7e7227bdd0bd599db0caaa623a046d2df671d0df74f"
    $a4="09fea83718f1b4114f27a68c07bd10063a163a124b048ef0cb318bf94a61c42076b8caa8475c045de1c42feacc3352ab824c907491e1ad3dee476fe1406006ac"
    $a5="c7b3b5b9a223a4f06084976070d22bd7d1fe67e524594c5014632c106ffa65e1cc496e2dc89d4fd831e416adbf5e3cfd685ffcb3dc15274523e34a4cbb63d6c0"
    $a6="666739b339fe6627cf41757e1ba7617680836e0de9c5ea8e64ab5ef334efeaf53c65c387a275c8154946efb769617df43eeb7f25472d78172e08bedff6e87272"
    $a7="d181a4fc59dca216a22f993bf18b902aec9beff0d70be72cbaad69a1fcd53d4831433e9d7d52c57d8f61b660122f0603c5e42db5e16b8c7d4ed5428e1b4ab077"
    $a8="e36ac69210f52ff081cf7e811a791f766e6d56a960ef58ad08447ff60fe9c6ee58bccea8dedb04f4bb30c2d4c26dea2a43908970d1d5968aa1555626d0c66c1e"
    $a9="6162eb4b9377a7c411410c77e310652d31da64a51df77d3b5713f4b9291923fac30c67b26e9f544643957c7ebc5424edbf44a9b563e05ef74917d39ce3d4529a"
    $a10="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
    $a11="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
    $a12="eb4deacd551f08b2efcace8249486b5e33a470825a2dccd91da3659bae6558025169e9f4fa126b5195e6ff0addfb8a72439d5903dbb466a85f290c152d464b78"
    $a13="1c50ab60c2cebb875c56a2dab7accd17de4c8940deb0d158d628dc103fca18af78dd0fe95129123fb1408989a282544c6b22843c3dc443d835f6886802a9a9fa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}