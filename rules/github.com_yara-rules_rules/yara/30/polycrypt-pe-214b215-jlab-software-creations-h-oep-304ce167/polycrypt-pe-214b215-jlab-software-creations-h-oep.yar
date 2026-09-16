import "pe"
rule PolyCrypt_PE_214b215_JLab_Software_Creations_h_oep: PEiD
{
    strings:
        $a = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
    condition:
        $a at pe.entry_point

}