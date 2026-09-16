import "pe"
rule _ASPack_v107b_
{
	meta:
		description = "ASPack v1.07b"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D B8 03}
		$1 = {90 90 75}
		$2 = {90 75}
		$3 = {90 75 01 FF}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point or $3 at pe.entry_point
}