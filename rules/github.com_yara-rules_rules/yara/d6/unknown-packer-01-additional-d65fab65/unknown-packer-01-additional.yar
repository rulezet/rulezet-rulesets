import "pe"
rule Unknown_packer_01_additional: PEiD
{
    strings:
        $a = { EB ?? ?? BE ?? ?? BF ?? ?? 2E }
    condition:
        $a at pe.entry_point

}