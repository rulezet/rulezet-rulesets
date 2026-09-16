import "pe"
rule SecureEXE_30_ZipWorx: PEiD
{
    strings:
        $a = { E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}