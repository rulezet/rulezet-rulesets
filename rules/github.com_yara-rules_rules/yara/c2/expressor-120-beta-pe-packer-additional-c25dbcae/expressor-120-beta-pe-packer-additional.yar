import "pe"
rule eXPressor_120_Beta_PE_Packer_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }
    condition:
        $a at pe.entry_point

}