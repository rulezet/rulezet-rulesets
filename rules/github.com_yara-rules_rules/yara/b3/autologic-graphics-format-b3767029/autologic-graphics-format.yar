import "pe"
rule AutoLogic_Graphics_format: PEiD
{
    strings:
        $a = { FF 04 00 07 }
    condition:
        $a at pe.entry_point

}