import "pe"
rule ASProtect_v12x_New_Strain: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }
    condition:
        $a at pe.entry_point

}