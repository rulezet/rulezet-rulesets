rule aspr11_mte
{
	meta:
		author = "PEiD"
		description = "ASProtect 1.1 MTE -> Alexey Solodovnikov"
		group = "106"
		function = "3"
	strings:
		$a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
	condition:
		$a0
}