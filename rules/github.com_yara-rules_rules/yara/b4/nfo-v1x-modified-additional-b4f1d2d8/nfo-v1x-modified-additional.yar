import "pe"
rule NFO_v1x_modified_additional: PEiD
{
    strings:
        $a = { 60 9C 8D 50 }
    condition:
        $a at pe.entry_point

}