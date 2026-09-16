import "pe"
rule AMGC_Archive: PEiD
{
    strings:
        $a = { AD 36 22 00 }
    condition:
        $a at pe.entry_point

}