import "pe"
rule Upack_v037_v038_Beta_Strip_base_relocation_table_Option_: PEiD
{
    strings:
        $a = { 52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08 }
    condition:
        $a at pe.entry_point

}