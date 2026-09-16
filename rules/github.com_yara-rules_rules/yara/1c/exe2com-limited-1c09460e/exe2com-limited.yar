import "pe"
rule EXE2COM_Limited: PEiD
{
    strings:
        $a = { BE ?? ?? 8B 04 3D ?? ?? 74 ?? BA ?? ?? B4 09 CD 21 CD 20 }
    condition:
        $a at pe.entry_point

}