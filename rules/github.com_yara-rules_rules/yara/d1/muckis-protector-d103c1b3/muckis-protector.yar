import "pe"
rule muckis_protector: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }
    condition:
        $a at pe.entry_point

}