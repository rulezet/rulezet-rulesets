import "pe"
rule GX_Protector_12_GurueXe: PEiD
{
    strings:
        $a = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }
    condition:
        $a at pe.entry_point

}