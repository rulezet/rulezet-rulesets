import "pe"
rule _DOS32_v33_DOSExtender_and_Loader_
{
	meta:
		description = "DOS32 v.3.3 DOS-Extender and Loader"
	strings:
		$0 = {0E 1F FC 9C 5B 8B C3 80 F4 ?? 50 9D 9C 58 3A E7 75 ?? BA ?? ?? B4 09 CD 21 B4 4C CD 21}
	condition:
		$0 at pe.entry_point
}