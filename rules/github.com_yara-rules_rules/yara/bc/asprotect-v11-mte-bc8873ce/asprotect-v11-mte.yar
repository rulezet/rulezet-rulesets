import "pe"
rule ASProtect_v11_MTE: PEiD
{
    strings:
        $a = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
    condition:
        $a at pe.entry_point

}