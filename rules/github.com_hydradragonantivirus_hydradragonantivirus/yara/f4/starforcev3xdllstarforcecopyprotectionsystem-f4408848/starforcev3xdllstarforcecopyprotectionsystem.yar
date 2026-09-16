import "pe"
rule StarForceV3XDLLStarForceCopyProtectionSystem
	{
	strings:
			$a0 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }

	condition:
			$a0 at (pe.entry_point)
	}