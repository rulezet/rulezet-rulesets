import "pe"
rule Upack_Patch_Dwing: PEiD
{
    strings:
        $a = { 81 3A 00 00 00 02 00 00 00 00 }
        $b = { 2A A3 F2 54 CE }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}