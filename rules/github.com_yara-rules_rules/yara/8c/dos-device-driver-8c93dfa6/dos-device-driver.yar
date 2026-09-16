import "pe"
rule DOS_Device_Driver: PEiD
{
    strings:
        $a = { FF FF FF FF }
    condition:
        $a at pe.entry_point

}