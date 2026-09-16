import "pe"
rule UPX_Protector_v10x: PEiD
{
    strings:
        $a = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
        $b = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}