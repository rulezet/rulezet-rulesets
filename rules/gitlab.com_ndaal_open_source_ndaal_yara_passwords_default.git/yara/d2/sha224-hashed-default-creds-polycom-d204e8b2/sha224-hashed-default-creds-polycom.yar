rule sha224_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a1="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a2="11882960fbd93ad1606c66d9021f6281515a7d3a2c766881c597e33d"
    $a3="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a4="664d8f3cb0b98e5ed4204a2490993720a40dd297c859bbabb05ed987"
    $a5="a3090f99d2ce0958fa0939e99861203510fe54958a937abaa0bae06d"
    $a6="3cc27ba47fd4d99add33ea2fc6b94b1ddcd92598df48568e70c35ee4"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="09e8afd1a285e7f260f65e8de0e97fc01637360157b411cca9516f73"
    $a9="3778689d047eb9e58cfd5240ab3dd8fd84e1cdcdf0dc53ccecf97770"
    $a10="e7bedacebad77e3bc61d1e27db602019c6e0fc954d6c856bd2719968"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}