import "pe"
rule FASM : flat assembler {
	meta:
		author = "_pusher_"
		date = "2016-01"
		description = "http://flatassembler.net"
				condition:
		(
				(pe.linker_version.major == 1) and ((pe.linker_version.minor >= 60) and (pe.linker_version.minor < 80))
		) 
		}