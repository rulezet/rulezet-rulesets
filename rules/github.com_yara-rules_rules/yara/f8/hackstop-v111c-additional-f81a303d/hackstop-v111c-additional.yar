import "pe"
rule HACKSTOP_v111c_additional: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB }
    condition:
        $a at pe.entry_point

}