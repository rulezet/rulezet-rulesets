import "pe"
rule VBOX_v43_v46: PEiD
{
    strings:
        $a = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
        $b = { ?? ?? ?? ?? 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40 }
        $c = { 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 8B C4 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}