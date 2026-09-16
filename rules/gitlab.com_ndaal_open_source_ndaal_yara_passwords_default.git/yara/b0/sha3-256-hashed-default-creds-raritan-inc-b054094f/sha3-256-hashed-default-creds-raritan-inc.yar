rule sha3_256_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea4924c8a593b7b108fb0504ad8fc158a426a954504621da8426fc0999cea173"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="ea4924c8a593b7b108fb0504ad8fc158a426a954504621da8426fc0999cea173"
    $a3="9d1c35af18eefeab7224f81320cb7fe2135b6bb21851876a2806cdf65c5d074a"
    $a4="e9f06df6fee11b6dea41c31259d3595441905c185999c1d6f14a003a78ef3a77"
    $a5="54bbd8d043c2f16607ee065e62e5f6158d12ed55991fd33e6573f4022c269e31"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}