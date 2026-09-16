import "pe"
rule _Cryptic_20__Tughack_
{
	meta:
		description = "Cryptic 2.0 -> Tughack"
	strings:
		$0 = {B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3}
	condition:
		$0 at pe.entry_point
}