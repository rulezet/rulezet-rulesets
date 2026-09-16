import "pe"
rule Aluwain_v809_additional: PEiD
{
    strings:
        $a = { 8B EC 1E E8 ?? ?? 9D 5E }
    condition:
        $a at pe.entry_point

}