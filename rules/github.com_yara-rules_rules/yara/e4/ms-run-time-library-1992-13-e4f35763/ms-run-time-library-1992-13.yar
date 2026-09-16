import "pe"
rule MS_Run_Time_Library_1992_13: PEiD
{
    strings:
        $a = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21 }
    condition:
        $a at pe.entry_point

}