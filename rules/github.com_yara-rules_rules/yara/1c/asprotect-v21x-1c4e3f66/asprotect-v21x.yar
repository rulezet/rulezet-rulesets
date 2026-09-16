import "pe"
rule ASProtect_v21x: PEiD
{
    strings:
        $a = { BB E9 60 9C FC BF B9 F3 AA 9D 61 C3 55 8B }
    condition:
        $a at pe.entry_point

}