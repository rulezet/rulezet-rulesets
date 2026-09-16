rule PEiD_01522_PE_Crypter_
{
    meta:
        description = "[PE-Crypter]"
        ep_only = "true"
    strings:
        $a = {60 E8 00 00 00 00 5D EB 26}
    condition:
        $a
}