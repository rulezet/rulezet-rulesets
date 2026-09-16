import "pe"
rule PECrc32_088_ZhouJinYu_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }
    condition:
        $a at pe.entry_point

}