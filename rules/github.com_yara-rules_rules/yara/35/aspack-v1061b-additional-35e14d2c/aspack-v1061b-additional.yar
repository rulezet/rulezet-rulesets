import "pe"
rule ASPack_v1061b_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
    condition:
        $a at pe.entry_point

}