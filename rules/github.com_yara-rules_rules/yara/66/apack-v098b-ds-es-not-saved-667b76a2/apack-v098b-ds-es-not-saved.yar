import "pe"
rule aPack_v098b_DS_ES_not_saved: PEiD
{
    strings:
        $a = { 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75 }
    condition:
        $a at pe.entry_point

}