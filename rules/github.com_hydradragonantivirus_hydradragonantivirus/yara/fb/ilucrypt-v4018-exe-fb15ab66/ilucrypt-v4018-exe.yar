import "pe"
rule _iLUCRYPT_v4018_exe_
{
	meta:
		description = "iLUCRYPT v4.018 [exe]"
	strings:
		$0 = {8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81}
	condition:
		$0 at pe.entry_point
}