import "pe"
rule _ASYLUM_Music_File_v10_
{
	meta:
		description = "ASYLUM Music File v.1.0"
	strings:
		$0 = {41 53 59 4C 55 4D 20 4D 75 73 69 63 20 46 6F 72 6D 61 74 20 56 31 2E 30 00}
	condition:
		$0 at pe.entry_point
}