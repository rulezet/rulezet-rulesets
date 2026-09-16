import "pe"
rule WARNING_TROJAN_XiaoHui: PEiD
{
    strings:
        $a = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }
    condition:
        $a at pe.entry_point

}