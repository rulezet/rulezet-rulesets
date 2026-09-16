import "pe"
rule CExe_v10a_TinyWare_Inc: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A 00 FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }
    condition:
        $a at pe.entry_point

}