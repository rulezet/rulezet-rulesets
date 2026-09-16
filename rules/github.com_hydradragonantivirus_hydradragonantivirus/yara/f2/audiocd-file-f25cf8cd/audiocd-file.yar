import "pe"
rule _AudioCD_file_
{
	meta:
		description = "Audio-CD file"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74}
	condition:
		$0 at pe.entry_point
}