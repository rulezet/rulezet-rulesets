import "pe"
rule AsCrypt_v01_SToRM_5: PEiD
{
    strings:
        $a = { 83 ?? ?? E2 ?? ?? E2 ?? FF }
    condition:
        $a at pe.entry_point

}