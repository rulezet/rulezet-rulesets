import "pe"
rule BopCrypt_v10_additional: PEiD
{
    strings:
        $a = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}