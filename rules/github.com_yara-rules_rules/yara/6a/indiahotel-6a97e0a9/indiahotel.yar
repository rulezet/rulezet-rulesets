import "pe"
rule IndiaHotel
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "8a4fc5007faf85e07710dca705108df9fd6252fe3d57dfade314120d72f6d83f"

	strings:
	

	$fileExtractorArraySetup = {6A 0A 8D [5-6] 68 10 02 00 00 50 E8}

	condition:
		$fileExtractorArraySetup in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}