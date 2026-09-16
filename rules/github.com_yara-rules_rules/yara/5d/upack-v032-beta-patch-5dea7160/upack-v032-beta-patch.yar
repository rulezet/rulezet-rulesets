import "pe"
rule Upack_v032_Beta_Patch: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5 }
    condition:
        $a at pe.entry_point

}