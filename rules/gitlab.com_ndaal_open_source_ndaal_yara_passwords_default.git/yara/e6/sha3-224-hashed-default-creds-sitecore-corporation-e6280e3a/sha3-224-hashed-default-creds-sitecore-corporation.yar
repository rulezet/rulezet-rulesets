rule sha3_224_hashed_default_creds_sitecore_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sitecore_corporation."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ec94b5ae7bae885e5b1fdeaa6fc2ca2af27febfdb7cdfaa6745fd52"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b"
    $a3="efd6b06cde0475722fe362790928b5f8f25cbc508ec94190080fdbab"
    $a4="8ec94b5ae7bae885e5b1fdeaa6fc2ca2af27febfdb7cdfaa6745fd52"
    $a5="5ae8dcccea571a5f29262890677fd912111bf56dcb1806837efc5bb6"
    $a6="af81fd2b118fc4b3ed11bd42e7c056de57e29fcde0b0f236adaa4e25"
    $a7="ce39fdde24b909908febae7dfa2e296f4da3413e3a9bf028418ecbc1"
    $a8="35fd6f346c0b2fa77a32a1c8d961d08450da1cd6494afca64b57955f"
    $a9="566366711efac35a5a00d667c33e522c7179324ca90dadb9dfda415a"
    $a10="c3835c6f733db2d1f556e5b2f32f11ad59ad0a7e996a25376951cd81"
    $a11="76f7c81b268005b14b786c133ba671d2804ff28c3f01d714c3e39f58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}