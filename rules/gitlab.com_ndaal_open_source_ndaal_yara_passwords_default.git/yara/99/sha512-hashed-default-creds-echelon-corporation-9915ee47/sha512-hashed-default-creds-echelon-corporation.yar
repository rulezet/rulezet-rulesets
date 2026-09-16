rule sha512_hashed_default_creds_echelon_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for echelon_corporation."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
    $a1="148f853770daf506693ab8e09f613e7df214b423babf090c536f320cdf576b5fb1784f65ed8268984913bd8e75bb7815ec5205b212b922a22834d5b6e399102d"
condition:
    ($a0 and $a1)
}