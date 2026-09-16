rule sha3_384_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f2388e9d87457e92b81f99e9f073ac39bcc5e94039f9f350c909b64e0afbafee050a745ffc0906afc5adda0a3a30dad9"
    $a1="3b7f166f1f53674024eaea0a08486166ab1b9f28f26ba984cf05cd0872ccd3ba5a222fda1bbe4c741d091988594c9cf4"
    $a2="3f1fc78f8999010f75a8506228ecd49beb282bb608d2c6dee87f3254c7ac4896a77e19e76e95157cac7536ce6589fc41"
    $a3="529eee81848c0b9c70ab004466c7565cbf93ebbd22742047c814635ac508b1b8c006075f8681f72b6a558b879f19958c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}