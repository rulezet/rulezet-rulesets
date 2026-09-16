import "pe"
rule ExeTools_v21_Encruptor_by_DISMEMBER_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? 5D 83 ?? ?? 1E 8C DA 83 ?? ?? 8E DA 8E C2 BB ?? ?? BA ?? ?? 85 D2 74 }
    condition:
        $a at pe.entry_point

}