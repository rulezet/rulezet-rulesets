import "pe"
rule AutoDesk_Animation_file: PEiD
{
    strings:
        $a = { ?? ?? ?? 00 12 AF ?? ?? 40 01 C8 }
        $b = { 00 12 AF ?? ?? 40 01 C8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}