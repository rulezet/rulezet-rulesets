rule sha384_hashed_default_creds_raspberry_pi_foundation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raspberry_pi_foundation."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="22462d58277a3c531c3370898fef482bd6d681db1eec407d05f05bc65df30fdd32b5155e966f83537f0cb97436fdc328"
    $a1="520dc475f13a853cf460b09609ac16cabf78cad4ded3a44e258bbb099669e79a6fde03cc13ca1b845829dde32e6320f7"
condition:
    ($a0 and $a1)
}