import "pe"
rule ZOO_Archive: PEiD
{
    strings:
        $a = { 5A 4F 4F }
    condition:
        $a at pe.entry_point

}