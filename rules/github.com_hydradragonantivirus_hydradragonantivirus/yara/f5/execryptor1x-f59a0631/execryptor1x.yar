rule execryptor1x
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.x.x -> SoftComplete Developement"
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }
	condition:
		$a0
}