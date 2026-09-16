import "pe"
rule Vx_XRCV1015_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B }
    condition:
        $a at pe.entry_point

}