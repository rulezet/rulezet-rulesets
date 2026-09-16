import "pe"
rule Unknown_file_protector_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? BE ?? ?? BF ?? ?? 2E }
    condition:
        $a at pe.entry_point

}