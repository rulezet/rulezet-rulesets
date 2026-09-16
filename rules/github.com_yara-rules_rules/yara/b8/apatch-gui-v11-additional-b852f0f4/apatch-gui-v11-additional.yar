import "pe"
rule APatch_GUI_v11_additional: PEiD
{
    strings:
        $a = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
    condition:
        $a at pe.entry_point

}