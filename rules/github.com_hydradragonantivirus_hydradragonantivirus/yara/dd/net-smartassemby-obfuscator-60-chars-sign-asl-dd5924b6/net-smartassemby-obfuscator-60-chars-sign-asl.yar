import "pe"
rule _NET_SmartAssemby_Obfuscator_60_chars_sign_ASL_
{
	meta:
		description = ".NET SmartAssemby Obfuscator 6.0 (chars) sign ASL"
	strings:
		$0 = {50 6F 77 65 72 65 64 20 62 79 20 53 6D 61 72 74 41 73 73 65 6D 62 6C 79 20 36}
	condition:
		$0 at pe.entry_point
}