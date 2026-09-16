rule base64_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="QURPTklT"
    $a1="QlBNUw=="
    $a2="ZGFzdXNyMQ=="
    $a3="ZGFzdXNyMQ=="
    $a4="ZGIyYWRtaW4="
    $a5="ZGIyYWRtaW4="
    $a6="ZGIyZmVuYzE="
    $a7="ZGIyZmVuYzE="
    $a8="ZGIyaW5zdDE="
    $a9="ZGIyaW5zdDE="
    $a10="ZGIyaW5zdDE="
    $a11="ZGIycGFzcw=="
    $a12="ZGIyaW5zdDE="
    $a13="ZGIycGFzc3dvcmQ="
    $a14="ZGIyaW5zdDE="
    $a15="ZGIycHc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}