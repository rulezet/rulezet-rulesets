import "pe"
rule Netopsystems_FEAD_Optimizer_additional: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 BB 00 00 40 00 8B }
    condition:
        $a at pe.entry_point

}