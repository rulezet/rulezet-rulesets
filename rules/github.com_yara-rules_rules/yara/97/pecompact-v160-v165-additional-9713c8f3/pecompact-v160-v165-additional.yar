import "pe"
rule PECompact_v160_v165_additional: PEiD
{
    strings:
        $a = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }
    condition:
        $a at pe.entry_point

}