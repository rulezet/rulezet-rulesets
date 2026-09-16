import "pe"
rule eXPressor_v12_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
    condition:
        $a at pe.entry_point

}