import "pe"
rule Microsoft_Windows_Enhanced_Metafile: PEiD
{
    strings:
        $a = { 01 00 00 00 58 }
    condition:
        $a at pe.entry_point

}