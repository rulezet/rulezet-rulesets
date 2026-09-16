import "pe"
rule PKZIP_Archive: PEiD
{
    strings:
        $a = { 50 4B 03 04 }
    condition:
        $a at pe.entry_point

}