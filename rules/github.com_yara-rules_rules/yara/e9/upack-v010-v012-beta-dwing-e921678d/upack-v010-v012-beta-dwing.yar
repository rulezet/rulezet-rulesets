import "pe"
rule Upack_v010_v012_Beta_Dwing: PEiD
{
    strings:
        $a = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }
    condition:
        $a at pe.entry_point

}