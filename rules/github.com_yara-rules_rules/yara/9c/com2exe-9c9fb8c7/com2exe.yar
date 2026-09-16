import "pe"
rule COM2EXE: PEiD
{
    strings:
        $a = { F0 FF FE FF }
    condition:
        $a at pe.entry_point

}