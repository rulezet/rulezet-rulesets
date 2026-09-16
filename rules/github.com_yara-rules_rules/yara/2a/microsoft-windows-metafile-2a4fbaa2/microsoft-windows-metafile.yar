import "pe"
rule Microsoft_Windows_Metafile: PEiD
{
    strings:
        $a = { D7 CD C6 9A }
    condition:
        $a at pe.entry_point

}