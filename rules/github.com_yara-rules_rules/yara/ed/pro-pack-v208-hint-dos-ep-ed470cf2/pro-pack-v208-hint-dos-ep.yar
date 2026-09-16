import "pe"
rule PRO_PACK_v208_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }
    condition:
        $a at pe.entry_point

}