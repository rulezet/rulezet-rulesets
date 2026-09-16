import "pe"
rule StarForce_V3X_DLL_StarForce_Copy_Protection_System_: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}