import "pe"
rule Setup2Go_Installer_Stub: PEiD
{
    strings:
        $a = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }
    condition:
        $a at pe.entry_point

}