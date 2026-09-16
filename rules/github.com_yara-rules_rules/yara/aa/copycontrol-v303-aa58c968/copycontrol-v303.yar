import "pe"
rule CopyControl_v303: PEiD
{
    strings:
        $a = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }
    condition:
        $a at pe.entry_point

}