rule ThinstallVirtualizationSuite3_0x_3_330__ThinstallInc_
{
	meta:
		author = "PEiD"
		description = "Thinstall Virtualization Suite 3.0x - 3.330 -> Thinstall Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? FF FF E9 90 FF FF FF CC CC }
	condition:
		$a0
}