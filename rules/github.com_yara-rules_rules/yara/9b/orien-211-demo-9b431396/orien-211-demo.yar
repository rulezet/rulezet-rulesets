import "pe"
rule ORiEN_211_DEMO: PEiD
{
    strings:
        $a = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }
    condition:
        $a at pe.entry_point

}