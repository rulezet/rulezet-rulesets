import "pe"
rule _MOD_8_Track_Oktatracker_music_file_
{
	meta:
		description = "MOD 8 Track Oktatracker music file"
	strings:
		$0 = {4F 43 54}
	condition:
		$0 at pe.entry_point
}