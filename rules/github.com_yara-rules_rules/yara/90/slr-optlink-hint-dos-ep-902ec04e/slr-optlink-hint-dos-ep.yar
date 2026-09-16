import "pe"
rule SLR_OPTLINK_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB B4 30 CD 21 }
    condition:
        $a at pe.entry_point

}