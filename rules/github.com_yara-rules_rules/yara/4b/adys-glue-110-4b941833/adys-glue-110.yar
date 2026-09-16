import "pe"
rule Adys_Glue_110: PEiD
{
    strings:
        $a = { 2E ?? ?? ?? ?? 0E 1F BF ?? ?? 33 DB 33 C0 AC }
    condition:
        $a at pe.entry_point

}