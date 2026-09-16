rule sha3_384_hashed_default_creds_nokia
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nokia."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a1="18116244f5df2ae4f2650679c451d9a31aa03b9b4c66db3045e88afa9acb9a2f7782c85b82ff10ee3f76727af52ffb8d"
    $a2="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a3="16ecf09833cfef4d951cef07cb9f6808c2486aed0fdf70fa1422db442ef8abfe0f36a5677afb555f695291e3804eaed5"
    $a4="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a5="4a7fa999178fa9e19fb8cdca4cb9eab9976c4f738563687e4d36be911be8e1a57f4aec666bd134946030419a12f2cee7"
    $a6="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a7="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a8="88bcc6999eb878c6f2f8c6b4e4d53c16cef8b404a2e2a535184f613516821f6582f2b2047becefda5dbf1d578607b824"
    $a9="ee45e3ab25285f3457a73f9cd40362598a53ff5e11aa929ea92eddca1df8f96f129dab5e0dc10bf91a8f1584caf046f3"
    $a10="5b6ec279e869c119bb09329a67bc3008bf193b9d08cc125760576e557ab01985cf3dd9d949e4e3b859ad8d68abd48d04"
    $a11="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a12="859f4acd5845ee70358ee2c50f345047e4c52cdbf7940dc7e5585d7008af14ee6a4a5d88aa12dff4c50eecf6c5c42e1b"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="161609f9697539edd5e03b6f5bfd1735f5c6037e0b00027c45a80386d5ebdcd3eb4bde062710914c7f37bd45f1c8021d"
    $a15="a7a88afadf5e6559987e2a7e031337a99ef1085074cbdf43ad046e40156897de70d34663a97c3427756090b3782cb92c"
    $a16="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
    $a17="2c53361516b9069b5d11f3f70dc2b8ee39e5487145d52f4cf7b026bb8e3a6227670243749beb93475d66ce8ab0ddcb44"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}