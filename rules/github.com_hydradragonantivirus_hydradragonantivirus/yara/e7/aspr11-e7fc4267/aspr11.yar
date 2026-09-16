rule aspr11
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 -> Alexey Solodovnikov"
		group = "106"
		function = "0"
	strings:
		$a0 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }
	condition:
		$a0
}