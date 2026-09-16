import "pe"
rule WinRAR_SFX: PEiD
{
    strings:
        $a = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 }
    condition:
        $a at pe.entry_point

}