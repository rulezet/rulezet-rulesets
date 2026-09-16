import "pe"
rule NX_PE_Packer_v10: PEiD
{
    strings:
        $a = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }
    condition:
        $a at pe.entry_point

}