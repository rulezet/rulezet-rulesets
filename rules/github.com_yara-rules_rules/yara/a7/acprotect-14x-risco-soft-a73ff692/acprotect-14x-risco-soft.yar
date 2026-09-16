import "pe"
rule ACProtect_14x_RISCO_soft: PEiD
{
    strings:
        $a = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }
        $b = { 47 53 44 31 02 00 11 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}