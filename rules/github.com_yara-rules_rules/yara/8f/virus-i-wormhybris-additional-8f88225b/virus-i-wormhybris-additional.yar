import "pe"
rule VIRUS_I_WormHybris_additional: PEiD
{
    strings:
        $a = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }
    condition:
        $a at pe.entry_point

}