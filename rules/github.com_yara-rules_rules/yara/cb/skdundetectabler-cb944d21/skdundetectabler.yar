import "pe"
rule SkDUndetectabler : SkDrat {
	meta:
		author = "_pusher_"
	condition:
		(
		borland_delphi or 		((pe.linker_version.major == 6) and (pe.linker_version.minor == 0 ))
		)
		and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size < filesize) and
						( 
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000739)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000745)  or
				(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000C00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00002A00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00001A00)
		)
		and
				( 
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x6275 or
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x4057
		)
}