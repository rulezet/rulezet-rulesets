import "pe"
rule ActiveMARK : Trymedia Systems Inc
{
	meta:
		author="_pusher_"
		date = "2016-08"		
	strings:
		$a0 = { 00 54 4D 53 41 4D 56 4F 48 A4 9B FD FF 26 24 E9 D7 F1 D6 F0 D6 AE BE FC D6 DF B5 C1 D0 1F 07 CE EF EE DD DE 4F F1 D1 AE BE }
	condition:
		$a0 at (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)
}