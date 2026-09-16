rule sha224_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f06a391a1f76cbfa4cdccf29b53c4208882dd2a7365f2589f2d8970b"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="9ad61cf005a3d3d4fda9f006212bc8361ce3baee909f9a3a8e6f8b2e"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="a866c5323df6eedc8e5e8d703e43f9323c83781941000e3ae52d2bad"
    $a9="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a10="026538e5757f5fff4745bd506644010d39776027c1d3b302d4959dd3"
    $a11="101111087b7707e181db649390773370f8b4742746f0e88793b8c27e"
    $a12="379a46e85d7be930571ab4ef689f10b258ea99318a014e62274479d9"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a14="d35e70814fe2e2013fca23dd9b7cb67985f65f4aadd7c7d5d0f4caf9"
    $a15="a16b0181d196e34fc0b662184adcba6e440801e1c3cb7a47cabc162c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}