rule sha512_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b4b47425204debb72cf4bbb14d32520110b357378c2009e90838d10ec658c72b2243897e93682a0e00bb811338ad6791cbf5bfa5808380164804b0381a68457c"
    $a1="a0ad1858d8e5490e51e6c79bbe244e4efa67c19baaf6206d71be662c41262615c20819da94984531b5d2762cf0d885085ab5fcf7751b239bae23587e51dd6823"
    $a2="b4b47425204debb72cf4bbb14d32520110b357378c2009e90838d10ec658c72b2243897e93682a0e00bb811338ad6791cbf5bfa5808380164804b0381a68457c"
    $a3="1d141f905badd7d0541a9afb1eebde8019f179220a2342395259acd3e737959e584869b4a32488eddf86afb515fca8b47e3aeb75d82649b636d2dd198e3141f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}