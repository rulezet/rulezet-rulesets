import "pe"
rule BJFnt_v13: PEiD
{
    strings:
        $a = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }
        $b = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}