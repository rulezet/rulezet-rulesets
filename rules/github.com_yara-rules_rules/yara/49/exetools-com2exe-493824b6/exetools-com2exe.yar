import "pe"
rule ExeTools_COM2EXE: PEiD
{
    strings:
        $a = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60 }
    condition:
        $a at pe.entry_point

}