rule ldap_sha1_hashed_default_creds_honeywell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeywell."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a1="{SHA}s6ypLHk+4OmxqbCl9fwETgUUDfM="
    $a2="{SHA}kOcz4zguFdMTYxa2FMr/5evWRCo="
    $a3="{SHA}wm7V4pGCAxhPw11Pq6sKOEH8ARo="
    $a4="{SHA}2DoQTKGSkyRmzB4wi0l1e6jOOfA="
    $a5="{SHA}xjt3tGGa6HFtPwqZ4XODwq2OcoI="
    $a6="{SHA}NWdeaPS1r3uZXZIFrQ/EOELxZFA="
    $a7="{SHA}+s6D7jAUvcj5ggPMlOLokiJFLpA="
    $a8="{SHA}nXU0LBA6BQz7CbBZYLuV1twTNbY="
    $a9="{SHA}vbg/yEDVUNLnsH1VDCLHEvoCiic="
    $a10="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a11="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}