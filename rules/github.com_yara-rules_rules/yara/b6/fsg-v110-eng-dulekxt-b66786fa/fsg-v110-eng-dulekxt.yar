import "pe"
rule FSG_v110_Eng_dulekxt: PEiD
{
    strings:
        $a = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
    condition:
        $a at pe.entry_point

}