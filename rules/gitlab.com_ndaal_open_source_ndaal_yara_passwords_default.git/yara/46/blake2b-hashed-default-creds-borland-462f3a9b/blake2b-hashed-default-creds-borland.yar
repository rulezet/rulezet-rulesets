rule blake2b_hashed_default_creds_borland
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fc060574f55a849c98a530babd7cf605d4efbba9bae2357cef498295f5e2936d5c6ca8fedc3ace3cea70a1b6479a8dc7153d4acb1035cdf409f8c70a6ebc60f5"
    $a1="26e0e8245915ed5eb4832976c444c3dfe51302b94672a0199c0bb62f3b66cef6bda064ec6c71dbe0116a30ee48d580eea600b795ded11ece4faaeefa2ad516ad"
    $a2="fc060574f55a849c98a530babd7cf605d4efbba9bae2357cef498295f5e2936d5c6ca8fedc3ace3cea70a1b6479a8dc7153d4acb1035cdf409f8c70a6ebc60f5"
    $a3="01f3a87debcac43d202623639ca66fe3c9c4350104913e3dc7a714be3f8be6ffb7795b1d57fe8206e37fb927f3940c343a10fac2a758719f33c28d0fb270cce6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}