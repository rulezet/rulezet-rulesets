import "pe"
rule _tElock_V098_Special_Build__forgot__heXer_
{
	meta:
		description = "tElock V0.98 Special Build -> forgot & heXer"
	strings:
		$0 = {E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA}
	condition:
		$0 at pe.entry_point
}