import "pe"
rule ASPack_v106b_additional: PEiD
{
    strings:
        $a = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        $a at pe.entry_point

}