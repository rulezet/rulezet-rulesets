import "pe"
rule Nullsoft_PiMP_Stub_SFX: PEiD
{
    strings:
        $a = { 81 EC ?? ?? ?? ?? 53 55 56 }
    condition:
        $a at pe.entry_point

}