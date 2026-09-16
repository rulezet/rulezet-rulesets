import "pe"
rule FreeHand_Graphics_format: PEiD
{
    strings:
        $a = { 41 47 44 32 }
    condition:
        $a at pe.entry_point

}