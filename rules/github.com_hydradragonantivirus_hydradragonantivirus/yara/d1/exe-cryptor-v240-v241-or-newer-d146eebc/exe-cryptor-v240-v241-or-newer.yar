import "pe"
rule _EXE_Cryptor_v240__v241_or_newer_
{
	meta:
		description = "EXE Cryptor v2.4.0 - v2.4.1 (or newer)"
	strings:
		$0 = {E8 3B FF FF FF 05 ?? ?? 00 00 FF E0 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 04 00 00 00 FF FF FF FF 5E C3}
	condition:
		$0 at pe.entry_point
}