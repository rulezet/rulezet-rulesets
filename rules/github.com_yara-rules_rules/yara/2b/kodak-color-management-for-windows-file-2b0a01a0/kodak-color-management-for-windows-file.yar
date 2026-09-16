import "pe"
rule Kodak_Color_management_for_Windows_file: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? 4B 43 4D 53 }
        $b = { 4B 43 4D 53 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}