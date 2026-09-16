import "pe"
rule Windows_Write_file: PEiD
{
    strings:
        $a = { ?? BE 00 00 00 AB 00 00 00 }
        $b = { BE 00 00 00 AB 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}