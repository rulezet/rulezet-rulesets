rule sha224_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="019f944c2edea1f9445201c5b669f429004ee68e7d1b478d4b9448de"
    $a1="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a2="39504c0938c4aadf733870b3be9327e9723ff6d7f7ec92536025639f"
    $a3="f287cef4d4cd13b203a0d9e0d9be0b76532f55fb302aeda5e68a99f4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}