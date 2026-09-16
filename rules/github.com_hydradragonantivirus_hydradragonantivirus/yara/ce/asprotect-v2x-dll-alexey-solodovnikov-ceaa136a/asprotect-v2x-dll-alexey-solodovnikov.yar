import "pe"
rule _ASProtect_V2X_DLL__Alexey_Solodovnikov_
{
	meta:
		description = "ASProtect V2.X DLL -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD}
	condition:
		$0 at pe.entry_point
}