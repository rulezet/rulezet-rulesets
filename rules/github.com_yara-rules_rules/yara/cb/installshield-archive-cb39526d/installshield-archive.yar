import "pe"
rule InstallShield_Archive: PEiD
{
    strings:
        $a = { 2A AB 79 D8 }
    condition:
        $a at pe.entry_point

}