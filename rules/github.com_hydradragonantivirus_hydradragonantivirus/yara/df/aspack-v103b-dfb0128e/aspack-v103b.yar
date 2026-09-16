import "pe"
rule _ASPack_v103b_
{
	meta:
		description = "ASPack v1.03b"
	strings:
		$0 = {60 E8 5D 81 ED CE 3A 44 B8 C8 3A 44 03 C5 2B 85 B5 3E 44 89 85 C1 3E 44 80 BD AC 3E}
		$1 = {60 E8 5D 81 ED B8 03 C5 2B 85 12 9D 89 85 1E 9D 80 BD 08}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}