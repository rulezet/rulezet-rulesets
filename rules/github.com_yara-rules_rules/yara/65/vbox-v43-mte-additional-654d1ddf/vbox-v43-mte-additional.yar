import "pe"
rule VBOX_v43_MTE_additional: PEiD
{
    strings:
        $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }
    condition:
        $a at pe.entry_point

}