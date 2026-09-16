rule ep2
{
	meta:
		author = "PEiD"
		description = "EP 2.0 -> CoDe_Inside"
		group = "117"
		function = "0"
	strings:
		$a0 = { 6A ?? 60 E9 01 01 }
	condition:
		$a0
}