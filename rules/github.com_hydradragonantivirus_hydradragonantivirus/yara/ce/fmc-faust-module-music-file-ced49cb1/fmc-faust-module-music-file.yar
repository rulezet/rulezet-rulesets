import "pe"
rule _FMC_Faust_Module_music_file_
{
	meta:
		description = "FMC Faust Module music file"
	strings:
		$0 = {46 4D 43 21}
	condition:
		$0 at pe.entry_point
}