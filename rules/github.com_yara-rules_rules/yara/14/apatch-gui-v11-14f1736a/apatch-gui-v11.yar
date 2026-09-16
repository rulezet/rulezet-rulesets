import "pe"
rule APatch_GUI_v11: PEiD
{
    strings:
        $a = { 52 31 C0 E8 FF FF FF FF }
    condition:
        $a at pe.entry_point

}