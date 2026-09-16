rule sha224_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="419a856402c6af7f2ca44409770e2ec57e81964c13cdf674253d4056"
    $a1="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a2="63eab7b93113a149c3c5df0e30ca710b69ad88162c8721049a31f27d"
    $a3="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a4="4f574afca11cd46bf1d6767c5dad8b68a454f2e83cccf246ba8dd258"
    $a5="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}