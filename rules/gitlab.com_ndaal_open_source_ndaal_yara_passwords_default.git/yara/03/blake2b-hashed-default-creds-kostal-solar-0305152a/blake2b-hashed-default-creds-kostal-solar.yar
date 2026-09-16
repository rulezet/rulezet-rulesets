rule blake2b_hashed_default_creds_kostal_solar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kostal_solar."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1f165074883982251a573babc53e5bc88d06fc9d1d515f430f00156a82bebb05f260dff63b8569bf498a7ae658a511de6c32dc307466b5f7af8bc130c598f153"
    $a1="a29d22d088ee496d781f66b721cec6bbf515e9bedcd4126f9683944aa43f6d340c80de05723ae8f9684ec383ab7c22c469075b47b3c624e3af1514b879356348"
condition:
    ($a0 and $a1)
}