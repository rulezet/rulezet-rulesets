import "pe"
rule PE_Lock_NT_v204_additional: PEiD
{
    strings:
        $a = { EB ?? ?? BE ?? ?? BF ?? ?? 2E }
    condition:
        $a at pe.entry_point

}