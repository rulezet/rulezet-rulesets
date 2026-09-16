import "pe"
rule _Trilobytes_RNR_graphics_library_
{
	meta:
		description = "Trilobyte's RNR graphics library"
	strings:
		$0 = {84 10 ?? ?? ?? ?? ?? ?? ?? 10}
	condition:
		$0 at pe.entry_point
}