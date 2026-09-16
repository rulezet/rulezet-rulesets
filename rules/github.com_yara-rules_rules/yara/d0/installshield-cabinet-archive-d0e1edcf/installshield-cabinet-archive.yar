import "pe"
rule InstallShield_Cabinet_Archive: PEiD
{
    strings:
        $a = { 49 53 63 }
    condition:
        $a at pe.entry_point

}