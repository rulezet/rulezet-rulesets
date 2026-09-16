import "pe"
rule ASProtect_v11_MTEc_additional: PEiD
{
    strings:
        $a = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }
    condition:
        $a at pe.entry_point

}