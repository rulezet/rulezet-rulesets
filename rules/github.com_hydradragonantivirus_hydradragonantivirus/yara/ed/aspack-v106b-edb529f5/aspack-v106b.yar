import "pe"
rule _ASPack_v106b_
{
	meta:
		description = "ASPack v1.06b"
	strings:
		$0 = {90 90 75 ??}
		$1 = {90 90 90 75 ??}
		$2 = {60 E8 5D 81 ED EA A8 43 B8 E4 A8 43 03 C5 2B 85 78 AD 43 89 85 84 AD 43 80 BD 6E AD}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}