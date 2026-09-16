rule ldap_sha1_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}oy4KiMHwgqOrAbeudzg38UAIO6k="
    $a1="{SHA}2eiyldLrGqi638JYSC3QZOv5L/Y="
    $a2="{SHA}zlgx3+wxqQ/nqEREdZxMnEmfHWU="
    $a3="{SHA}P41b+3+nU2ixDRM/1hXJGTS5LXM="
    $a4="{SHA}rwTIju99VaKrfKJVWhpOMeJeAiQ="
    $a5="{SHA}lhOY+CRMY3s1bfPun5aNNIZH+Zg="
    $a6="{SHA}NQSI/bxRsohsrZrIzLPLhkXy7RU="
    $a7="{SHA}1jbFm1w9e1Cb1sNKC40MNgfp2kU="
    $a8="{SHA}zZWyhZb3YZbtoShmENVkOfcN0hE="
    $a9="{SHA}zZWyhZb3YZbtoShmENVkOfcN0hE="
    $a10="{SHA}I+Af9PjGuwMFgBY+bPqe7qY6itM="
    $a11="{SHA}I+Af9PjGuwMFgBY+bPqe7qY6itM="
    $a12="{SHA}fgu386wta+deZ4zOgoj/6tqBlPg="
    $a13="{SHA}fgu386wta+deZ4zOgoj/6tqBlPg="
    $a14="{SHA}sjq9v8COeY2AgBLHhIlCJRbTUeo="
    $a15="{SHA}sjq9v8COeY2AgBLHhIlCJRbTUeo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}