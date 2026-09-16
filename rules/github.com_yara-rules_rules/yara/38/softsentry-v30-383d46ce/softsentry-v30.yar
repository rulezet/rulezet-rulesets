import "pe"
rule SoftSentry_v30: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }
    condition:
        $a at pe.entry_point

}