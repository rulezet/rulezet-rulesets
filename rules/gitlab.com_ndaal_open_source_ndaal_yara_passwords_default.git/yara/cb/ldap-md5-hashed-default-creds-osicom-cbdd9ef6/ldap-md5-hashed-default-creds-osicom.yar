rule ldap_md5_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a1="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a2="{MD5}KSl/eG9K0VOEx0gMhKnSUw=="
    $a3="{MD5}rUL2aXsDW3WA5P75O+ILTQ=="
    $a4="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a5="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a6="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a7="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a8="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a9="{MD5}KSl/eG9K0VOEx0gMhKnSUw=="
    $a10="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a11="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a12="{MD5}j5v+nRNFI3yzsrIFhk2gdQ=="
    $a13="{MD5}CE4DQ6BIb/BVMN9scFyLtA=="
    $a14="{MD5}46/tAEewgFnQ+toQ9ADB5Q=="
    $a15="{MD5}4Mvw5i0DeW8x2kcJloK3Kw=="
    $a16="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a17="{MD5}rpS+PNUyzkoCWISBnrCMmA=="
    $a18="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a19="{MD5}y7Ee2H3IqV2BQAx/M8fBcQ=="
    $a20="{MD5}9gqTJj+6PuI7USYPbDnD4Q=="
    $a21="{MD5}z6UwE1i5/L56pFsc7qCIxg=="
    $a22="{MD5}LBfGOTdx7jBIrjTWs4DF7A=="
    $a23="{MD5}77KmhOSvt9VeYUf75aMy7g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}