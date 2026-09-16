rule blake2b_hashed_default_creds_digi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af68ece31a74067a0bf2343496f87c4244cac30d3cee7a86ee9b2a40b0e7eff42d1386e0147fa94ac24ce63265008b478ee612579cc8c39f62dff7dc13aa0555"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="bcbeaca672bd84fd482d08e78eb257f175f17fcb4989f77b0b465e19f6e21ad160368f4a89c984699a0cea8f55b9762d49527e3c8dd3441b3e35d2d0d729f755"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}