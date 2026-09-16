import "pe"
rule StarForce_V3X_StarForce_Copy_Protection_System_additional: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}