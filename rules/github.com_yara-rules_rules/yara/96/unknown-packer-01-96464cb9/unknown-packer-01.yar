import "pe"
rule Unknown_packer_01: PEiD
{
    strings:
        $a = { EB ?? ?? BE ?? ?? BF ?? ?? 2E }
    condition:
        $a at pe.entry_point

}