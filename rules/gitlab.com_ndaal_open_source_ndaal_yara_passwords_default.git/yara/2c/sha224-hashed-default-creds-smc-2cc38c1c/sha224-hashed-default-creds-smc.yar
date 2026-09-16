rule sha224_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a1="5fde807d89bc98fa829ab5c847c25c93c96faba025cd2e5a7f0d1ff5"
    $a2="d02105ca0dbbd0cc327b9e08133f58c8a8f0cde6f53ed0ed71d2e6de"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="cd67b76f75f4577b8c0f9541bb4658e24a34ee90a9fbe4f3a46bed80"
    $a7="a244a67f51a1100c52553ea5397c3590343c27b53d2f35bee284e47d"
    $a8="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="f0970a19af5844a88a7786fdaf2fbb6ac94a30e6ba8a38a7d1ab4954"
    $a11="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a12="464a4808d15d53e3a9ef3f3351a2dc9b59bf2ef819823f35c2948322"
    $a13="6e9642705c45d7b717574d3fa6ac9e0db4f5fb59253b3485d7881872"
    $a14="82d9c3ee2ca2513164aa2e8fa3c0d25e07f2d7393e816b4bedaf9415"
    $a15="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a16="d7fa4220dbdba075c082e72b446d4c022ecef55474fdf085de543015"
    $a17="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}