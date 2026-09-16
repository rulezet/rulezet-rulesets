rule sha384_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7276f879d844283681889a5c5f580f30d8bc469263f47dae6e240a99a4a7efd1507da0624d3d85475da900fc361e47f5"
    $a1="7276f879d844283681889a5c5f580f30d8bc469263f47dae6e240a99a4a7efd1507da0624d3d85475da900fc361e47f5"
    $a2="abccce632c2244a5968143be6a181ae13815db6f70562b3314e5d34a02bf77218ab60bc032bb2cc8ef0734aa1e65ba09"
    $a3="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}