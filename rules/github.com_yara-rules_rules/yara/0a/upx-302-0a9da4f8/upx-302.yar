import "pe"
rule UPX_302: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C }
    condition:
        $a at pe.entry_point

}