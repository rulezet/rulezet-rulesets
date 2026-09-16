rule TrojanWin32UrausySampleA
{
	meta:
		Description  = "Trojan.Urausy.sm"
		ThreatLevel  = "5"

	strings:
		$a = { 55 89 E5 53 56 57 83 0D ?? ?? ?? ?? 01 31 C0 5F 5E 5B C9 C2 04 00 }
		$b = { FF 15 ?? ?? ?? ?? 09 C0 0F 84 ?? ?? ?? ?? 8B 75 ?? 89 C3 6A 01 6A FF 6A 05 56 E8 }

	condition:
		$a and $b
}