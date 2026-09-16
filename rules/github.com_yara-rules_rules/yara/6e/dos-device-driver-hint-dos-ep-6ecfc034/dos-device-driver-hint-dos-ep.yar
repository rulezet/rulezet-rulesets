import "pe"
rule DOS_Device_Driver_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FF FF FF FF }
    condition:
        $a at pe.entry_point

}