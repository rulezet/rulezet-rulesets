rule md5_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6bde2a01c490e177d6dcd15c149c129"
    $a1="e6bde2a01c490e177d6dcd15c149c129"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="08b5411f848a2581a41672a759c87380"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="4b583376b2767b923c3e1da60d10de59"
    $a6="4a96374e6cedd5ea88c3409a317a304e"
    $a7="4b583376b2767b923c3e1da60d10de59"
    $a8="cd0c6092d6a6874f379fe4827ed1db8b"
    $a9="cd0c6092d6a6874f379fe4827ed1db8b"
    $a10="1d0258c2440a8d19e716292b231e3190"
    $a11="54b53072540eeeb8f8e9343e71f28176"
    $a12="d41e98d1eafa6d6011d3a70f1a5b92f0"
    $a13="54b53072540eeeb8f8e9343e71f28176"
    $a14="5f4dcc3b5aa765d61d8327deb882cf99"
    $a15="54b53072540eeeb8f8e9343e71f28176"
    $a16="44327681dd926addc2a74225226220f7"
    $a17="54b53072540eeeb8f8e9343e71f28176"
    $a18="4a96374e6cedd5ea88c3409a317a304e"
    $a19="4a96374e6cedd5ea88c3409a317a304e"
    $a20="4bc3fb252edf8e4f12acf85c0af633cf"
    $a21="4bc3fb252edf8e4f12acf85c0af633cf"
    $a22="64c5b12b7729e5076eaa577436042951"
    $a23="4a96374e6cedd5ea88c3409a317a304e"
    $a24="44327681dd926addc2a74225226220f7"
    $a25="4a96374e6cedd5ea88c3409a317a304e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}