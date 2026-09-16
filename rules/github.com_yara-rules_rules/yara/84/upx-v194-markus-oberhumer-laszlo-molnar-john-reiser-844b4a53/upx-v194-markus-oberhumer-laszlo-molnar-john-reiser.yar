import "pe"
rule UPX_V194_Markus_Oberhumer_Laszlo_Molnar_John_Reiser: PEiD
{
    strings:
        $a = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
    condition:
        $a at pe.entry_point

}