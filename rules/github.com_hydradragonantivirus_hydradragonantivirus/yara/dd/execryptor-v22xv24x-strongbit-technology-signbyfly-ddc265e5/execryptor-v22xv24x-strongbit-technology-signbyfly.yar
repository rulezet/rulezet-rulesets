import "pe"
rule _EXECryptor_V22XV24X__StrongBit_Technology__SignByfly_
{
	meta:
		description = "EXECryptor V2.2X-V2.4X -> StrongBit Technology * Sign.By.fly"
	strings:
		$0 = {E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 04 00 00 00 FF FF FF FF 5E C3}
	condition:
		$0 at pe.entry_point
}