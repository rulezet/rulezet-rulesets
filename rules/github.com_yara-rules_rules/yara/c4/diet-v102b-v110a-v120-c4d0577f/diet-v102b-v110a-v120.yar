import "pe"
rule DIET_v102b_v110a_v120: PEiD
{
    strings:
        $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }
    condition:
        $a at pe.entry_point

}