import "pe"
rule _StarForce_V3X_DLL__StarForce_Copy_Protection_System_
{
	meta:
		description = "StarForce V3.X DLL -> StarForce Copy Protection System"
	strings:
		$0 = {E8 ?? ?? ?? ?? 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}