import "pe"
rule eXPressor_v14_CGSoftLabs_: PEiD
{
    strings:
        $a = { 65 58 50 72 2D 76 2E 31 2E 34 2E }
    condition:
        $a at pe.entry_point

}