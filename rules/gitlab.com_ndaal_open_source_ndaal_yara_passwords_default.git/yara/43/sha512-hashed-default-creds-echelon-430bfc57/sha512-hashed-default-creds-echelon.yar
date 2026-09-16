rule sha512_hashed_default_creds_echelon
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a1="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a2="c4658ba1be4cf84908c075c2ae2b3d8489a4710dbefd2de93dcd9d14d88fe926f5be68848bc48b633556a4f35f44cd6ccdf65486f9c5796ebbf1fa20466c219c"
    $a3="2b4dfa3e3dc5474deff172459e10e4e95d3f2da8a6d65cffb9459440b0807455a3ebaba7c4de11526bf07b7403c07cd423c63069e818dd4b640f5b17f701e39e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}