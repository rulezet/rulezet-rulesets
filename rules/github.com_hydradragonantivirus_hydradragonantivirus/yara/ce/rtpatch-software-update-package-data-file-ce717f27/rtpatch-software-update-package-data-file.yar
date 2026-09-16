import "pe"
rule _RTPatch_software_update_package_data_file_
{
	meta:
		description = "RTPatch software update package data file"
	strings:
		$0 = {4B 2A}
	condition:
		$0 at pe.entry_point
}