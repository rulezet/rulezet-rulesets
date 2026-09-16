rule sha384_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0740da5db546b7a2c239bd57526b94c08ab7320fe9e646c3187625b0b681ef85f5a835ee4f7375f062bca6a05b3073d9"
    $a1="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
condition:
    ($a0 and $a1)
}