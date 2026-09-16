import "pe"
rule InstallShield_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 2A AB 79 D8 }
    condition:
        $a at pe.entry_point

}