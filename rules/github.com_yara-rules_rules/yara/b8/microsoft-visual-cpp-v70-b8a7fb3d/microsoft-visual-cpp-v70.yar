import "pe"
rule Microsoft_Visual_Cpp_v70: PEiD
{
    strings:
        $a = { 6A 68 }
        $b = { 6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}