import "pe"
rule Vx_GRUNT1Family_additional: PEiD
{
    strings:
        $a = { 01 B9 ?? 00 31 17 }
    condition:
        $a at pe.entry_point

}