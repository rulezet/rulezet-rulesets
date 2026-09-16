import "pe"
rule VBOX_v43_MTE: PEiD
{
    strings:
        $a = { 36 3E 26 8A C0 60 }
        $b = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}