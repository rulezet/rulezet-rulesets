import "pe"
rule PENightMare_v13_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }
    condition:
        $a at pe.entry_point

}