rule ssentry3
{
	meta:
		author = "PEiD"
		description = "SoftSentry 3.0 -> 20/20 Software"
		group = "171"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }
	condition:
		$a0
}