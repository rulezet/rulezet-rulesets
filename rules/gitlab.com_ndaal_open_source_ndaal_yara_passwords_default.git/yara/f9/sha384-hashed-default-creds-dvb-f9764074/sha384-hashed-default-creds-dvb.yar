rule sha384_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2db08bbcfa55242de63ce96e05cc22110bff4e2c2ecc6898171a37051b15da0d56aee41080a38149863df759666f7598"
    $a1="619e017f112d67ebdf4d67dd061742453011e99b6ae5e9095d29aa070988600f20a6fda395a9dfae8b23e3577de98377"
    $a2="200f488374f9e029da0598f3957eddc99e1abb891a079f8aac2ef73362c15bfec6fb1be4ec864e10a8c86fd46fba8dd2"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}