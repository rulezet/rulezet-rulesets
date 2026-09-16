rule sha3_512_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c056828e33dfe0798d4380e3dd37f2086bde9947d5320708c8afbde286aeaf8c0ab78521d2fde6472cdac57a5f066a01adc7cfb7d768fb187ec4e68a7137bda5"
    $a1="3a6a797f2e60f766597dca5af1ffdb10232c5f639059676a9153f856b17dd8c0c4b3e5a5f4ef9fb1ff3a64c1ec2d4b6a83054d8f935e919fc29e6377a99f0bb4"
    $a2="f15999c451b7d531d05c7e10dcf63219867d98820e724c5ba2f8c5518bad2088fef915cf911f025d854fcc9335fba674fe422aa7ceadc2f1a3e05d35b6bb8aad"
    $a3="3a6a797f2e60f766597dca5af1ffdb10232c5f639059676a9153f856b17dd8c0c4b3e5a5f4ef9fb1ff3a64c1ec2d4b6a83054d8f935e919fc29e6377a99f0bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}