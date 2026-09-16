rule sha1_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8605c4f2a895654f392416e343dc600d7a38396f"
    $a1="8605c4f2a895654f392416e343dc600d7a38396f"
    $a2="2da0b68df8841752bb747a76780679bcd87c6215"
    $a3="2da0b68df8841752bb747a76780679bcd87c6215"
    $a4="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a5="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a6="a9bd7a5b583cbe082e2c850595c71a6818626f10"
    $a7="a9bd7a5b583cbe082e2c850595c71a6818626f10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}