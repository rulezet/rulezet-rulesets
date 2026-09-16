import "pe"
rule _EPack_14_lite_final__by_6aHguT_
{
	meta:
		description = "!EPack 1.4 lite (final) - by 6aHguT"
	strings:
		$0 = {33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8}
	condition:
		$0 at pe.entry_point
}