import "pe"
rule UPX_Alternative_stub_Laszlo_Markus: PEiD
{
    strings:
        $a = { EB 02 EB EA EB FC 8A 06 }
    condition:
        $a at pe.entry_point

}