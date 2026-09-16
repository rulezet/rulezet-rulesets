import "pe"
rule AntiVirus_Vaccine_v103_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }
    condition:
        $a at pe.entry_point

}