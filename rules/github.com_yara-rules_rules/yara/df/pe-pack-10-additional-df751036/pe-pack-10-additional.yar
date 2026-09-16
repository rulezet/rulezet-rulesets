import "pe"
rule PE_PACK_10_additional: PEiD
{
    strings:
        $a = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }
    condition:
        $a at pe.entry_point

}