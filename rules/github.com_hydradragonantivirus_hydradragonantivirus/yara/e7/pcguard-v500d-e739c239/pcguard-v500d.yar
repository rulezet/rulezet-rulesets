import "pe"
rule _PCGuard_v500d_
{
	meta:
		description = "PC-Guard v5.00d"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D EB}
	condition:
		$0 at pe.entry_point
}