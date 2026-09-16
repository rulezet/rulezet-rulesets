import "pe"
rule UPX_v0896_v102_v105_v122_DLL_Laszlo_Markus: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        $a at pe.entry_point

}