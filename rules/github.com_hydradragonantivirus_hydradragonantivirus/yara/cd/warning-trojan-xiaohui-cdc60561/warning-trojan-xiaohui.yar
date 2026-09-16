import "pe"
rule _WARNING__TROJAN__XiaoHui_
{
	meta:
		description = "WARNING -> TROJAN -> XiaoHui"
	strings:
		$0 = {60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00}
	condition:
		$0 at pe.entry_point
}