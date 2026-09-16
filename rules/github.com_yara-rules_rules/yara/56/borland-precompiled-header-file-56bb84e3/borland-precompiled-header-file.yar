import "pe"
rule Borland_precompiled_header_file: PEiD
{
    strings:
        $a = { 54 50 53 }
    condition:
        $a at pe.entry_point

}