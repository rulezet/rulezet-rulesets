rule sha512_hashed_default_creds_cyberpower
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyberpower."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
    $a1="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
    $a2="ff5bb17dfe26eba3c6ac9641a70a96d92b1e7f219899ec58141b643c67d8d6fc21dd5f731d095d0f07eefd771be1bab459a4e7e8bb95d9768e6498b106c9f923"
    $a3="798d897d0c3a79759b0f5ceba243adaea41e8898ffddd67a55104bbe0500cdbdf70dd9a701d7338813fc46dd33b2e56f5d0066472fcebf6470469454c5a993fb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}