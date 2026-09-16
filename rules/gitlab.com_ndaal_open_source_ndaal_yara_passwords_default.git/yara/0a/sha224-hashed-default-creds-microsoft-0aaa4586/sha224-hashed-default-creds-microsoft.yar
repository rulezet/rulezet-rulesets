rule sha224_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a1="537d21880c207ca6f1620fb66775e8eea6eb0394be15c277671dd27d"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a5="b814433fc0d4e2cf39757c3711c8af9522f2e760730f929255a9848b"
    $a6="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a7="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a8="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a9="1c95d70b4960a674e2c8a0e86c3a2ada419b9b7534912790666ed9bb"
    $a10="4cf7c11763549176ffee1d55608d7eb9d0b1166d96bf656863180349"
    $a11="4cf7c11763549176ffee1d55608d7eb9d0b1166d96bf656863180349"
    $a12="b87945fdb5d23cc40c1561895cc904d1a47815dd6b57fe76c418a21c"
    $a13="c7dd2cfe31cb55b8e77585868c1e67d35b07bd5dfaddc29eb9a6e5c7"
    $a14="1386e45ec7d12980a14ade12e3319d62e19aa056b522b1471abe899f"
    $a15="1386e45ec7d12980a14ade12e3319d62e19aa056b522b1471abe899f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}