import "pe"
rule PLINK86_1984_1985: PEiD
{
    strings:
        $a = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }
    condition:
        $a at pe.entry_point

}