import "pe"
rule VBOX_v43_v46_additional: PEiD
{
    strings:
        $a = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
    condition:
        $a at pe.entry_point

}