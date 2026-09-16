import "pe"
rule A_program_by_Jupiter_: PEiD
{
    strings:
        $a = { 2B C0 74 05 68 ?? ?? ?? ?? 50 }
    condition:
        $a at pe.entry_point

}