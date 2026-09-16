import "pe"
rule pen1
{
	meta:
		author = "PEiD"
		description = "PEncrypt 1.0 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { 60 9C BE ?? 10 40 ?? 8B FE B9 28 03 ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }
	condition:
		$a0 at pe.entry_point
}