import "pe"
rule FSG_v13_additional: PEiD
{
    strings:
        $a = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 }
    condition:
        $a at pe.entry_point

}