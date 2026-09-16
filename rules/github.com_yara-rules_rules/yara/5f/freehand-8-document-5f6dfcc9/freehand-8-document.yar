import "pe"
rule FreeHand_8_document: PEiD
{
    strings:
        $a = { 41 47 44 33 }
    condition:
        $a at pe.entry_point

}