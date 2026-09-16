rule telock_071b8
{
	meta:
		author = "PEiD"
		description = "tElock 0.71b8 -> tE!"
		group = "179"
		function = "0"
	strings:
		$a0 = { 60 E8 F3 10 00 00 C3 83 }
	condition:
		$a0
}