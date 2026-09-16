rule sha224_hashed_default_creds_weblogic_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic_web."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fd5afabd20815aa3fc49a278aef4f8c011766a118f14af3f673e006a"
    $a1="fd5afabd20815aa3fc49a278aef4f8c011766a118f14af3f673e006a"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="14695dc5a4b1d81de1e07388414a7a6926b40e953879dd4f40fecb12"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a6="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a7="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
    $a8="2929859b5d777b7acbc9deb2a63d9e7382b648bde3a0fbdc44418cac"
    $a9="2929859b5d777b7acbc9deb2a63d9e7382b648bde3a0fbdc44418cac"
    $a10="e33f021521d09ed907c106ba9e46a7ff70207db4555f0eaf3b8c5c15"
    $a11="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a12="bb3dde385e8be09d6a46a981d471fe621ee35f79d5423e2faeaa9e3f"
    $a13="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a14="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a15="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a16="1f531a3e37a0d190ac7324954eb727d124704c614d61bf3538741231"
    $a17="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a18="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a19="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a20="9849d2513b1c579da45230d3fb8aa8a5a380412a27befb41b0024c58"
    $a21="9849d2513b1c579da45230d3fb8aa8a5a380412a27befb41b0024c58"
    $a22="58cda4a7095eca3d3ca4530bcc50071fe126f3942564f1538be4a687"
    $a23="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
    $a24="1f531a3e37a0d190ac7324954eb727d124704c614d61bf3538741231"
    $a25="e58cf0b9c10eb7b968771c0edf2572f197b317faf4c6dfacefba2d10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}