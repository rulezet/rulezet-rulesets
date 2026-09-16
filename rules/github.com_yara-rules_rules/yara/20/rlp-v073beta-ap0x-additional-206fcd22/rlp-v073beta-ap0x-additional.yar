import "pe"
rule RLP_V073beta_ap0x_additional: PEiD
{
    strings:
        $a = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }
    condition:
        $a at pe.entry_point

}