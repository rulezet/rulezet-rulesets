import "pe"
rule PEiD_02152_StarForce_V3_X_DLL____StarForce_Copy_Protection_System_
{
    meta:
        description = "[StarForce V3.X DLL -> StarForce Copy Protection System]"
        ep_only = "true"
    strings:
        $a = {E8 ?? ?? ?? ?? 00 00 00 00 00 00}
    condition:
        $a at pe.entry_point
}