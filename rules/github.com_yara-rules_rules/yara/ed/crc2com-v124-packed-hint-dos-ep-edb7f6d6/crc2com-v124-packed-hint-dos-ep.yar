import "pe"
rule CRC2COM_v124_packed_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 8B FC 83 EF ?? 83 EC ?? BE ?? ?? B9 ?? ?? 57 F3 A4 5F FF E7 }
    condition:
        $a at pe.entry_point

}