import "pe"
rule tElock_v100: PEiD
{
    strings:
        $a = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 50 8B FE 68 78 01 59 EB 01 EB AC 54 E8 03 5C EB }
        $b = { E9 E5 E2 FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}