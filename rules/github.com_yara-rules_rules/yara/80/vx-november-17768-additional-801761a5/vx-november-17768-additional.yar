import "pe"
rule Vx_November_17768_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }
    condition:
        $a at pe.entry_point

}