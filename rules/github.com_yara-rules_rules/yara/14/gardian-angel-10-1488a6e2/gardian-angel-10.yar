import "pe"
rule Gardian_Angel_10: PEiD
{
    strings:
        $a = { 06 8C C8 8E D8 8E C0 FC BF ?? ?? EB }
    condition:
        $a at pe.entry_point

}