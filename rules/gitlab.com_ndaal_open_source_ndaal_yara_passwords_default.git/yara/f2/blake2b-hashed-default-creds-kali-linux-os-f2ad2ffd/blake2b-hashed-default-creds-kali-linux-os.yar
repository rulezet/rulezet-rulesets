rule blake2b_hashed_default_creds_kali_linux_os
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kali_linux_os."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1546bc4c13dd59a32ca1d372cbfd0f41cf2a5f08a7ffe53c46f441164b2e2f51898f5055de4fcdf326d26779f671e3b158981543f76e3b0038757f010d2e00fa"
    $a1="1546bc4c13dd59a32ca1d372cbfd0f41cf2a5f08a7ffe53c46f441164b2e2f51898f5055de4fcdf326d26779f671e3b158981543f76e3b0038757f010d2e00fa"
    $a2="27e200a377873d0925cc1d01852f2e15bd7125da124b40c05ddb2d051ef7f20fbc4d7de79cc53e71e5733c4da2f3db58515fa112df1c67022aa3f2d91aff7413"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}