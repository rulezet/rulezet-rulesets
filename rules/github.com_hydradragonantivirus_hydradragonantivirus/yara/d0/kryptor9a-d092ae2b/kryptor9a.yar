import "pe"
rule kryptor9a
{
	meta:
		author = "PEiD"
		description = "k.kryptor 9 / kryptor a -> r!sc & noodlespa"
		group = "128"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		$a0 at pe.entry_point
}