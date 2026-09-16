rule sha512_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="73461cc279e0e1b0d11ba54de652ccc047567f5380f6d6aa6f4f819aab92eaba19a7fda16ea0e6abd1dcd67d42b0928e2fe68a3fbe3afec7dbf325cab0abb364"
    $a1="528036fbe5a60298874181839fb37d70233dd65b8bb0761c7b0ce44242e0eb302a472cfceb5101b89487fcac90de294ea3f47893220d325bc293c46cd93d5796"
    $a2="86fb3bdfd18c375e452153b46e6ae45bb1e96aae0bca4ff19adc93f474c85f6cb6cd8f184fbfaac56e00df0d7cd480998959769aa0c206227254b62b1f29fca8"
    $a3="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}