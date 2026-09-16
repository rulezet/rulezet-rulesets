rule blake2b_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="687549276dae445405f821f9a1d3c2a886bba383a0efecd0e8f90236e9c4e5b80b0d836ab8223c1f0beef263eaafe146996822fab57489d35fdd530ef027e77f"
    $a1="4c04d5b478474dedc75b5af52560718ba9a30f64e558bc4a1a91630d11bdfd6b85f06e1ffcfd7143692c335f8e9765eb67d5250b82f6e1fb7c313e5146fd2da2"
condition:
    ($a0 and $a1)
}