import "pe"
rule ASProtect_V2X_Registered_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3 }
    condition:
        $a at pe.entry_point

}