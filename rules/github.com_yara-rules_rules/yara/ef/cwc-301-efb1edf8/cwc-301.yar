import "pe"
rule CWC_301: PEiD
{
    strings:
        $a = { FA 16 1F 26 A1 02 00 83 E8 40 8E D0 FB 06 16 07 BE F0 03 8B FE B9 10 00 F3 A4 07 36 8C 06 FC 03 8B D8 8C CA 36 03 16 F0 03 36 8B 2E F2 03 FD 8B C5 3D 00 10 76 03 B8 00 10 2B E8 2B D0 2B D8 8E DA 8E C3 B1 03 D3 E0 8B C8 D1 E0 48 48 8B F0 8B }
    condition:
        $a at pe.entry_point

}