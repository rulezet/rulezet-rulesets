import "pe"
rule _Microsoft_C_198889_
{
	meta:
		description = "Microsoft C (1988/89)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 02 CD 20 BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73}
	condition:
		$0 at pe.entry_point
}