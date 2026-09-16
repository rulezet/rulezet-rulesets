rule pesh025_x
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.25 Heuristic Mode -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D ?? 56 ?? ?? ?? ?? ?? ?? ?? ?? 8A ?? ?? 32 ?? 80 }
	condition:
		$a0
}