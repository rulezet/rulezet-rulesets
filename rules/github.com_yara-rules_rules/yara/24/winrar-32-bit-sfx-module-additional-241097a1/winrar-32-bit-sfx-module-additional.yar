import "pe"
rule WinRAR_32_bit_SFX_Module_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? 00 00 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}