rule sha512_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e53125d5130816a5e6ab3f160ed93d1f498edc3fdacf89ec901c749a09a2d01e1713a3c454f221af5a8069a9fc4829e648a8fe51cd43e35ab4e6c11e8f4bd54"
    $a1="ac73f333529ff75720ee24f8963653d237a1b34ec2956a1143fed5ca5d4a53ea2c7b40594f2c258a0f34db0d49452d49cf43581e431da691df4abd63aa2e5144"
condition:
    ($a0 and $a1)
}