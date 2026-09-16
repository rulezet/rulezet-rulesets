import "pe"
rule Borland_Delphi_v20_additional: PEiD
{
    strings:
        $a = { 06 FC 8C C8 BA ?? ?? 03 D0 52 BA ?? ?? 52 BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 }
    condition:
        $a at pe.entry_point

}