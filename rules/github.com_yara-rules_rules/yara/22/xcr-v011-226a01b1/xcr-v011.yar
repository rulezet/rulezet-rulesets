import "pe"
rule XCR_v011: PEiD
{
    strings:
        $a = { 60 9C E8 8B DD 5D 81 ED 89 }
        $b = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}