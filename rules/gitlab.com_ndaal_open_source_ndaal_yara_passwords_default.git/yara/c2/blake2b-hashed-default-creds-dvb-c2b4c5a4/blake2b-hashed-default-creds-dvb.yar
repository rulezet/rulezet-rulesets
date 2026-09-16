rule blake2b_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62f543dcb309f5179725b992c941d218e7d7e41985870407f1a8e898c213e72bd43dd09dfeb403938e5210fc7aa191e30537a57c37232487e1f5ead2dcb23de5"
    $a1="c62fceedf1529641035ec9127a692b908068a07184728ffb9252fa7707edda55a5b3ca48aa52943d4016abbd9709664a399c63c401d2e128d9b77876bbcbf0c4"
    $a2="fce873e6840870a9efde5f6161622900f0e3959f96d920c83266ea4efc269858524fcfdfa74253360c207d4856b1b0f3484cd3773f74fc1326b488d2fd1dc6f9"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}