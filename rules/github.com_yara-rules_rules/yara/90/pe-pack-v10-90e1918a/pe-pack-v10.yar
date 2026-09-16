import "pe"
rule PE_Pack_v10: PEiD
{
    strings:
        $a = { FC 8B 35 70 01 40 83 EE 40 6A 40 68 30 }
        $b = { 74 ?? E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}