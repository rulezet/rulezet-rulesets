rule sha3_384_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8736dc03fd6bcbb8a86d7a16ad795c208f1b482bfcc2a855b2fee12dee37531ed80891ea46bda836277e2cb220cec5e1"
    $a1="7de6d3572939afe738e3a12af2157678d00834060887476eb84ce5805b47ff51c9c8dce8abcacaf0dee3722cce44274d"
    $a2="8736dc03fd6bcbb8a86d7a16ad795c208f1b482bfcc2a855b2fee12dee37531ed80891ea46bda836277e2cb220cec5e1"
    $a3="6179e192f720a8a2ec1f0a4fee2e9b7caf9c025334df38526bc320fa345ee8fa226fd5f0bee18a409a858c68e6634b36"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}