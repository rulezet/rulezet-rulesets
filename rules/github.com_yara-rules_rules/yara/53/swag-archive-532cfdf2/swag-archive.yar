import "pe"
rule SWAG_Archive: PEiD
{
    strings:
        $a = { ?? ?? 2D 73 77 31 2D }
        $b = { 2D 73 77 31 2D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}