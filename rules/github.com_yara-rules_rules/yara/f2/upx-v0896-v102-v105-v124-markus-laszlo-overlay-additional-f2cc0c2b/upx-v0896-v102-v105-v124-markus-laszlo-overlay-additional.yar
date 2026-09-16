import "pe"
rule UPX_v0896_v102_v105_v124_Markus_Laszlo_overlay_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 ?? 8B 1E 83 ?? ?? 11 DB 72 ?? B8 01 00 00 00 01 DB 75 }
    condition:
        $a at pe.entry_point

}