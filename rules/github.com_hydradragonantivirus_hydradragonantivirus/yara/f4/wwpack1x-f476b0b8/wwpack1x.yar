rule wwpack1x
{
	meta:
		author = "PEiD"
		description = "WWPack32 1.x -> Piotr Warezak"
		group = "191"
		function = "0"
	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 }
	condition:
		$a0
}