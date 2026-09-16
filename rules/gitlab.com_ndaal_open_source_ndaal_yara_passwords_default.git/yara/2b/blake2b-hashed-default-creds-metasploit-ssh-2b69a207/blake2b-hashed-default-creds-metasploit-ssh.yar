rule blake2b_hashed_default_creds_metasploit_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for metasploit_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="191c46b7aa0d2f9ac3d5ec056d885ba4d0959a9a256b2f12da071cdef16fc990b9ebf1bd41a637b8af38dc453cc2a77270689e1bca2a1a2fc038e6e8a4d988f0"
    $a1="191c46b7aa0d2f9ac3d5ec056d885ba4d0959a9a256b2f12da071cdef16fc990b9ebf1bd41a637b8af38dc453cc2a77270689e1bca2a1a2fc038e6e8a4d988f0"
    $a2="43c36c46544ba3dd7db6c773aff52327e5fc434aae1ac05e0320b789d206aec12004f7a7675864e6aa15c5159c0b124ef2b0e0894327932effed6692f8aeaf65"
    $a3="43c36c46544ba3dd7db6c773aff52327e5fc434aae1ac05e0320b789d206aec12004f7a7675864e6aa15c5159c0b124ef2b0e0894327932effed6692f8aeaf65"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}