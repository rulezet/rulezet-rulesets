import "pe"
rule XCR_v011_additional: PEiD
{
    strings:
        $a = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }
    condition:
        $a at pe.entry_point

}