import "pe"
rule SoftSentry_v211: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }
    condition:
        $a at pe.entry_point

}