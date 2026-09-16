import "pe"
rule Inbuild_v10_hard_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2 }
    condition:
        $a at pe.entry_point

}