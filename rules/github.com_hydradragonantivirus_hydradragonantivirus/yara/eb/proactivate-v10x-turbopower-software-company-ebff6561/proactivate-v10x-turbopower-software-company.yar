import "pe"
rule _ProActivate_V10X__TurboPower_Software_Company__
{
	meta:
		description = "ProActivate V1.0X -> TurboPower Software Company !"
	strings:
		$0 = {8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53}
	condition:
		$0 at pe.entry_point
}