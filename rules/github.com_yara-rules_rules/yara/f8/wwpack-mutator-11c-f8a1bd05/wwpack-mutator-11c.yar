import "pe"
rule WWPack_Mutator_11c: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 2E 80 00 00 00 00 00 00 00 75 F5 }
    condition:
        $a at pe.entry_point

}