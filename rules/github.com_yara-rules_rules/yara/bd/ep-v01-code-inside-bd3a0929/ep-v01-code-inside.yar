import "pe"
rule EP_v01_CoDe_Inside: PEiD
{
    strings:
        $a = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC AA 86 C4 }
    condition:
        $a at pe.entry_point

}