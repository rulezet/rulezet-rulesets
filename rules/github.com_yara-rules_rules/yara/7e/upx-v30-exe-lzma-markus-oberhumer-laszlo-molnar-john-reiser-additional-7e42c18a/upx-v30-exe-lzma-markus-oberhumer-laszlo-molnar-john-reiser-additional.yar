import "pe"
rule UPX_v30_EXE_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? 00 57 83 C3 04 53 68 ?? ?? ?? 00 56 }
    condition:
        $a at pe.entry_point

}