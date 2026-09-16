import "pe"
rule ExePack_10_: PEiD
{
    strings:
        $a = { 60 E8 36 FE FF FF C3 90 }
    condition:
        $a at pe.entry_point

}