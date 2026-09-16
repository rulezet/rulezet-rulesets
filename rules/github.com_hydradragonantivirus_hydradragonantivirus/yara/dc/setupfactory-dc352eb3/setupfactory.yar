import "pe"
rule SetupFactory : Indigo Rose Corperation
{
	meta:
		author="_pusher_"
		date = "2016-09"
		description = "Installer"
	strings:
		$a0 = { E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 00 01 02 03 04 05 }
	condition:
				$a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size > 0x500)
		

}