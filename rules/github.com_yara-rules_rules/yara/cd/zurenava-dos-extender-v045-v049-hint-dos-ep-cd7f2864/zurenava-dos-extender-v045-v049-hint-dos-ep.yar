import "pe"
rule Zurenava_DOS_Extender_v045_v049_Hint_DOS_EP: PEiD
{
    strings:
        $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9 }
    condition:
        $a at pe.entry_point

}