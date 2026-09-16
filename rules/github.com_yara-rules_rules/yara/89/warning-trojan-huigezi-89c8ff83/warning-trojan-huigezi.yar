import "pe"
rule WARNING_TROJAN_HuiGeZi: PEiD
{
    strings:
        $a = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }
    condition:
        $a at pe.entry_point

}