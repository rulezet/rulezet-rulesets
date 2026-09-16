import "pe"
rule DEF_v100_Eng_bartxt_additional: PEiD
{
    strings:
        $a = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }
    condition:
        $a at pe.entry_point

}