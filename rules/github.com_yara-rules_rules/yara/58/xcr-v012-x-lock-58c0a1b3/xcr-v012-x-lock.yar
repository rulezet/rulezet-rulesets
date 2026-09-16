import "pe"
rule XCR_v012_X_Lock: PEiD
{
    strings:
        $a = { 60 9C E8 00 00 00 00 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }
    condition:
        $a at pe.entry_point

}