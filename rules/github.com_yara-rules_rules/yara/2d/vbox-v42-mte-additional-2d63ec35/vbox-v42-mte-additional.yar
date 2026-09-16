import "pe"
rule VBOX_v42_MTE_additional: PEiD
{
    strings:
        $a = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }
    condition:
        $a at pe.entry_point

}