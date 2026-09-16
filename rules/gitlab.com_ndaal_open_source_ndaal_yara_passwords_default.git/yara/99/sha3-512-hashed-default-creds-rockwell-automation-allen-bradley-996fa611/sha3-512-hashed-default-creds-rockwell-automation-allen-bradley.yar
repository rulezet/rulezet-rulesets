rule sha3_512_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="4019d67cbb61ae99be590560b56687fe53b6cede5b9a91cce74aea517fd8527d47c38a6b44e2fbff97aa7a8f59749d94b6a8545587c651f8892407bd15840b5f"
    $a5="257d6aa9c727c6833062be21aedc3d1f8eb3c58fa7af2db287bfb08c9f404409d23eb833633b7c5681c019c63f54bd556ffbf5b901655b5d7b0878f8353aef88"
    $a6="4019d67cbb61ae99be590560b56687fe53b6cede5b9a91cce74aea517fd8527d47c38a6b44e2fbff97aa7a8f59749d94b6a8545587c651f8892407bd15840b5f"
    $a7="83763184017775169d6e49acbe76a4d2fe548f08aba64bd88e11392ae5c3eaea6555e64942beb5d4ea6915ee97374447d2a561ddbea4608d5b6c4b36135f48b9"
    $a8="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a9="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a10="20b23956753615eadf495bf31ab307e1003e478b4f30d79074165e2402f2fa3f879ab44be88561f372a2b98cb9461afae8871d47636ac640c6d572ac10c333eb"
    $a11="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
    $a12="ccf16db31d1022f26c815beb938efe2b9725b277b4d4ab5fa3461da2d605e730db48d27c0aa67516fd48bc0f5e4eb7c963dd0aa31cfb525a423fc06693205261"
    $a13="2eef495e66d4871eb926902e7d6051aeba80d971a46c1c15afbbaa8931bb3010da7f56f92aa6c0e53f39115f4b6e6f78c2f64b66e9cdba9e15edd2d8e0aaaa60"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}