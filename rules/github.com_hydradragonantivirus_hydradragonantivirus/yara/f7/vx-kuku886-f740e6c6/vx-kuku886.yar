import "pe"
rule _Vx_Kuku886_
{
	meta:
		description = "Vx: Kuku.886"
	strings:
		$0 = {06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53}
	condition:
		$0 at pe.entry_point
}