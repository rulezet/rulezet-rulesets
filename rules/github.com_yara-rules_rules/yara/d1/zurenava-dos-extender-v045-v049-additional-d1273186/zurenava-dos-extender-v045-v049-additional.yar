import "pe"
rule Zurenava_DOS_Extender_v045_v049_additional: PEiD
{
    strings:
        $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9 }
    condition:
        $a at pe.entry_point

}