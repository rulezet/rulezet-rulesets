import "pe"
rule ProActivate_V10X_TurboPower_Software_Company_: PEiD
{
    strings:
        $a = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }
    condition:
        $a at pe.entry_point

}