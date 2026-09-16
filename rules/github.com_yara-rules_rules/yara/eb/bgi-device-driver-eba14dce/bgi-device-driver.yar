import "pe"
rule BGI_Device_Driver: PEiD
{
    strings:
        $a = { 70 6B 08 08 42 47 49 20 }
    condition:
        $a at pe.entry_point

}