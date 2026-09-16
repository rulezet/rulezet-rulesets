import "pe"
rule ASPack_v107b_DLL: PEiD
{
    strings:
        $a = { 90 90 90 75 }
        $b = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}