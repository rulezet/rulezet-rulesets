import "pe"
rule Compiled_InstallSHIELD_Installation_Script: PEiD
{
    strings:
        $a = { B8 C9 0C 00 }
    condition:
        $a at pe.entry_point

}