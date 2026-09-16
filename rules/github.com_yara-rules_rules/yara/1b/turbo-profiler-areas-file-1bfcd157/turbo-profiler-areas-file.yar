import "pe"
rule Turbo_Profiler_Areas_file: PEiD
{
    strings:
        $a = { 54 75 72 62 6F ?? 50 72 6F 66 69 6C 65 72 ?? 61 72 65 61 73 ?? 66 69 6C 65 }
    condition:
        $a at pe.entry_point

}