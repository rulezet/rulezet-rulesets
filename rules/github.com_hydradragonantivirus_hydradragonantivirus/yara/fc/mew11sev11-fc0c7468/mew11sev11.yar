rule MEW11SEv11
	{
	strings:
			$a0 = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }

	condition:
			$a0
	}