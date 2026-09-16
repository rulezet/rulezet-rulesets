rule mysql41_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*771329914CC356A42E444A2DC393606CDE70921E"
    $a3="*771329914CC356A42E444A2DC393606CDE70921E"
    $a4="*24C38244E2BC651D19BF7EB85DF78DF5FB01AA93"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*D2DFDFB8E2CCD75F076BF427D6E2DEB8C0B0D12D"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a9="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a10="*88D108DE81D643E6D250A0CE45BB50F96EBFDEF9"
    $a11="*88D108DE81D643E6D250A0CE45BB50F96EBFDEF9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}