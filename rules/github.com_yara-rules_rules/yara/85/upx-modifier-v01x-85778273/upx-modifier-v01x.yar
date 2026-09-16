import "pe"
rule UPX_Modifier_v01x: PEiD
{
    strings:
        $a = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
    condition:
        $a at pe.entry_point

}