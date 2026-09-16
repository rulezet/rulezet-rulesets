rule blake2b_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a1="8ba5b1805544195a73a4a523850d088f20f9a6618ddfb82fdedfaa7d3b90753a24869010a56c396928719fc85a2eb7160d5c800de75390032c7c41ee9b3fa41b"
    $a2="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a3="d0648eadb01154c79b43028fe4f35825d28c13cb0deb390ec754d89c6530c1ed5781844f20d0b133a5507bf08821e815cb69876c93faf003a84e4eadaf9b1031"
    $a4="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a5="f249d4309451f14dae44fe0fdd87cc1e34d2720d3b09e220237e81bb673879ecdbc7fb00efad6311ec531f219fd7088a02deeaa48399dae0b6dd6134bb9bcdff"
    $a6="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a7="bfbe0941012164e0ebe7773db6dd1e1847501917d16d34c44aab160b67a45091f69ec0bb56f4de91d6d5b953adabef6bc6867230d89f645e294300167937250d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}