import "pe"
rule _Norton_Speed_Disk_Configuration_file_
{
	meta:
		description = "Norton Speed Disk Configuration file"
	strings:
		$0 = {4E 6F 72 74 6F 6E 20 53 70 65 65 64}
	condition:
		$0 at pe.entry_point
}