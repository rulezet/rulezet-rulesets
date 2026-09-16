rule sha384_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afdc9c117556279082cb7d7c933ca5e651a1dbd9b78405ef3d90329997050a4a6396f980b55b84a9e77a4a6572c63b00"
    $a1="63fc52ff0cf52087b8b5fc53850973d288f6982570d4b469c8dac1e963a93772d928ae1350913b121946085f0a63b853"
    $a2="afdc9c117556279082cb7d7c933ca5e651a1dbd9b78405ef3d90329997050a4a6396f980b55b84a9e77a4a6572c63b00"
    $a3="dce4f511aaee332d23fdec1d839f2597e533203f550c63c0559c9017181d6b9f92f6244ce99f5d5adc7ee5be64edd58f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}