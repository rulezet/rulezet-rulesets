import "pe"
rule PE_Packer: PEiD
{
    strings:
        $a = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }
    condition:
        $a at pe.entry_point

}