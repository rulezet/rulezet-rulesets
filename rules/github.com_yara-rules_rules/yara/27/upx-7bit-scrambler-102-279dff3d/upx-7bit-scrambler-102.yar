import "pe"
rule UPX_7bit_Scrambler_102: PEiD
{
    strings:
        $a = { 0F 83 FA }
    condition:
        $a at pe.entry_point

}