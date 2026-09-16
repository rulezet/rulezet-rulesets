import "pe"
rule UPX_v30_DLL_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 C7 0B 00 00 60 BE 00 ?? ?? ?? 8D BE 00 ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}