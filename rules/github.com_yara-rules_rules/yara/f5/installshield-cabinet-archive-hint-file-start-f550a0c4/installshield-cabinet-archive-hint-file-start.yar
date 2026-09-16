import "pe"
rule InstallShield_Cabinet_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 53 63 }
    condition:
        $a at pe.entry_point

}