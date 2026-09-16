rule sobigf
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sobig.F_mm"
		group = "800"
		function = "23"
	strings:
		$a0 = { E9 25 E4 FF FF ?? ?? ?? 0B ?? B0 ED 1E EC 01 }
	condition:
		$a0
}