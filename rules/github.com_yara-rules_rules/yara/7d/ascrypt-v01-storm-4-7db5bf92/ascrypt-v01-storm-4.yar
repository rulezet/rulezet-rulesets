import "pe"
rule AsCrypt_v01_SToRM_4: PEiD
{
    strings:
        $a = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2 }
    condition:
        $a at pe.entry_point

}