rule sha3_224_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a2="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="841fa703d3d62efe1d04f7a2985425a0d22b9048461cb102c0e45bab"
    $a5="1bdf1b8e182ad1e5031e2c7e1649b5a4ad13a9c16d6b892c0942afd1"
    $a6="841fa703d3d62efe1d04f7a2985425a0d22b9048461cb102c0e45bab"
    $a7="bce7641fee5cb750cc2c9d89eff288973c09e09eb2e18d0037739262"
    $a8="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a9="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a10="3300785c377583971d8241d3dcf8cec718c3daf31392496c969452e7"
    $a11="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
    $a12="baf6f3dfdd1b9d6fa8a5cbdc360de08498674e681f042bb835d9fb96"
    $a13="812759e5a910946471cb20fcd97f6746555c7d365eea195fa96dfe3f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}