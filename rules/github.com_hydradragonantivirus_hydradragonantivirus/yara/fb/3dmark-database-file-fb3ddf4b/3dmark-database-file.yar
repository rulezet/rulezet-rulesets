import "pe"
rule _3DMark_Database_file_
{
	meta:
		description = "3DMark Database file"
	strings:
		$0 = {33 44 4D 61 72 6B 20 44 61 74 61 62 61 73 65 20 46 69 6C 65}
	condition:
		$0 at pe.entry_point
}