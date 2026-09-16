rule APT_Cloaked_SuperScan
	{
	meta:
		description = "Looks like a cloaked SuperScan Port Scanner. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		id = "96027f7d-822c-5c5e-acd9-cde8289c6b50"
	strings:
		$s0 = "SuperScan4.exe" wide fullword
		$s1 = "Foundstone Inc." wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and not filename contains "superscan"
}